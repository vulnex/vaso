/**
 * Tool-input → code/command sink tracing for JavaScript MCP server source
 * (MCP-005). A sink call (`eval`, `Function`, `vm.run*`, child_process
 * `exec`/`spawn`/…) is reported only when one of its arguments is derived from
 * tool input: a parameter of a tool handler (`server.tool(…, handler)`,
 * `registerTool`, `setRequestHandler(…, handler)`) or a parameter
 * conventionally named for input (`request`, `args`, `params`, …), followed
 * through variable bindings and reassignments.
 *
 * Replaces the old line regex that flagged any `${request.…}` template — which
 * fired on every `throw new Error(`Unknown tool: ${request.params.name}`)` and
 * missed the real sink when the tainted value was renamed first
 * (`const format = request.params.arguments.format; eval(`…${format}…`)`).
 */

import { createHash } from 'node:crypto';
import { parse } from '@babel/parser';
import _traverse from '@babel/traverse';
import type { Binding, NodePath } from '@babel/traverse';
import type { Node } from '@babel/types';

const traverse = typeof _traverse === 'function' ? _traverse : (_traverse as { default: typeof _traverse }).default;

export interface TaintedSink {
  line: number;
  snippet: string;
  /** Sink as written, e.g. `eval`, `child_process.exec`. */
  sink: string;
  /** How the argument reaches tool input, e.g. `format ← request`. */
  origin: string;
}

const INPUT_NAMES = new Set([
  'req', 'request', 'input', 'args', 'params', 'query', 'body', 'tool_input', 'toolInput', 'message',
]);

/** Methods whose function argument is an MCP tool/request handler. */
const HANDLER_REGISTRARS = new Set(['tool', 'registerTool', 'setRequestHandler']);

const CODE_SINKS = new Set(['eval', 'Function']);
const PROCESS_SINKS = new Set(['exec', 'execSync', 'spawn', 'spawnSync', 'execFile', 'execFileSync']);
const VM_SINKS = new Set(['runInNewContext', 'runInThisContext', 'runInContext', 'compileFunction']);
const SHELLS = /^(?:\/(?:usr\/)?bin\/)?(?:sh|bash|zsh|dash|cmd(?:\.exe)?|powershell(?:\.exe)?|pwsh)$/i;
const CHILD_PROCESS_NAMES = new Set(['child_process', 'childProcess', 'cp']);

const MAX_DEPTH = 8;
const MAX_CACHED = 1_000;
const cache = new Map<string, TaintedSink[]>();

export function findTaintedSinks(code: string, filename = 'unknown.js'): TaintedSink[] {
  const key = `${filename}\0${createHash('sha1').update(code).digest('base64')}`;
  const cached = cache.get(key);
  if (cached) return cached.map((s) => ({ ...s }));
  const results = analyze(code);
  if (cache.size >= MAX_CACHED) cache.delete(cache.keys().next().value!);
  cache.set(key, results);
  return results.map((s) => ({ ...s }));
}

/** Module specifier a binding was imported/required from, if any. */
function bindingModule(binding: Binding | undefined): string | undefined {
  if (!binding) return undefined;
  const parent = binding.path.parentPath?.node;
  if (parent?.type === 'ImportDeclaration') return parent.source.value;
  const node = binding.path.node;
  if (node.type === 'VariableDeclarator' && node.init?.type === 'CallExpression') {
    const { callee, arguments: args } = node.init;
    if (callee.type === 'Identifier' && callee.name === 'require' && args[0]?.type === 'StringLiteral') {
      return args[0].value;
    }
  }
  return undefined;
}

function isChildProcess(path: NodePath, name: string): boolean {
  const mod = bindingModule(path.scope.getBinding(name));
  if (mod) return mod === 'child_process' || mod === 'node:child_process';
  return CHILD_PROCESS_NAMES.has(name);
}

function analyze(code: string): TaintedSink[] {
  let ast: ReturnType<typeof parse>;
  try {
    ast = parse(code, {
      sourceType: 'unambiguous',
      plugins: ['typescript', 'jsx', 'decorators'],
      errorRecovery: true,
    });
  } catch {
    return [];
  }

  let lines: string[] | undefined;
  const lineText = (line: number): string => (lines ??= code.split('\n'))[line - 1]?.trim() ?? '';

  // Pass 1: functions registered as tool/request handlers — all their
  // parameters carry tool input.
  const handlers = new WeakSet<Node>();
  const results: TaintedSink[] = [];

  try {
    traverse(ast, {
      CallExpression(path) {
        const { callee, arguments: args } = path.node;
        if (callee.type !== 'MemberExpression' || callee.property.type !== 'Identifier') return;
        if (!HANDLER_REGISTRARS.has(callee.property.name)) return;
        for (const arg of args) {
          if (arg.type === 'ArrowFunctionExpression' || arg.type === 'FunctionExpression') handlers.add(arg);
        }
      },
    });

    const memo = new Map<Binding, string | null>();

    const bindingOrigin = (binding: Binding, depth: number): string | undefined => {
      if (memo.has(binding)) return memo.get(binding) ?? undefined;
      memo.set(binding, null); // cycle guard
      let origin: string | undefined;
      const name = binding.identifier.name;

      if (binding.kind === 'param') {
        if (handlers.has(binding.scope.block) || INPUT_NAMES.has(name)) origin = name;
      } else if (depth < MAX_DEPTH && (binding.kind === 'const' || binding.kind === 'let' || binding.kind === 'var')) {
        const declarator = binding.path;
        if (declarator.isVariableDeclarator()) {
          const init = declarator.get('init');
          const from = init.node ? expressionOrigin(init as NodePath, depth + 1) : undefined;
          if (from) origin = from === name ? name : `${name} ← ${from}`;
        }
        for (const violation of binding.constantViolations) {
          if (origin) break;
          if (violation.isAssignmentExpression()) {
            const from = expressionOrigin(violation.get('right'), depth + 1);
            if (from) origin = `${name} ← ${from}`;
          }
        }
      }

      memo.set(binding, origin ?? null);
      return origin;
    };

    // First tool-input-derived identifier referenced anywhere in `path`.
    const expressionOrigin = (path: NodePath, depth: number): string | undefined => {
      const visit = (id: NodePath): string | undefined => {
        if (!id.isIdentifier() || !id.isReferencedIdentifier()) return undefined;
        const binding = id.scope.getBinding(id.node.name);
        if (!binding) return INPUT_NAMES.has(id.node.name) ? id.node.name : undefined;
        return bindingOrigin(binding, depth);
      };
      let found = visit(path);
      if (found) return found;
      path.traverse({
        Identifier(id) {
          if (found) return id.stop();
          found = visit(id);
        },
        // A nested function's body doesn't flow into this value.
        Function(fn) { fn.skip(); },
      });
      return found;
    };

    const report = (path: NodePath<Node>, sink: string, candidates: NodePath[]): void => {
      for (const arg of candidates) {
        if (!arg.node) continue;
        const origin = expressionOrigin(arg, 0);
        if (origin) {
          const line = path.node.loc?.start.line ?? 0;
          results.push({ line, snippet: lineText(line).slice(0, 120), sink, origin });
          return;
        }
      }
    };

    // Pass 2: sinks.
    traverse(ast, {
      'CallExpression|NewExpression'(path: NodePath) {
        if (!path.isCallExpression() && !path.isNewExpression()) return;
        const callee = path.node.callee;
        const args = path.get('arguments') as NodePath[];

        if (callee.type === 'Identifier') {
          if (CODE_SINKS.has(callee.name)) return report(path, callee.name, args);
          if (PROCESS_SINKS.has(callee.name) && path.isCallExpression()) {
            return report(path, callee.name, processArgs(callee.name, args));
          }
          return;
        }

        if (callee.type === 'MemberExpression' && callee.object.type === 'Identifier' && callee.property.type === 'Identifier') {
          const obj = callee.object.name;
          const prop = callee.property.name;
          if (PROCESS_SINKS.has(prop) && isChildProcess(path, obj)) {
            return report(path, `${obj}.${prop}`, processArgs(prop, args));
          }
          if ((VM_SINKS.has(prop) || prop === 'Script') && (obj === 'vm' || bindingModule(path.scope.getBinding(obj))?.endsWith('vm'))) {
            return report(path, `${obj}.${prop}`, args);
          }
        }
      },
    });
  } catch {
    // Pathological ASTs (errorRecovery output) — report what was found so far.
  }

  return results;
}

/**
 * Arguments of a process sink that can carry an injection: the command for
 * `exec*`; for `spawn`/`execFile*` the program, plus its argv when the program
 * is a shell or `shell: true` is set (`spawn('sh', ['-c', input])`).
 */
function processArgs(sink: string, args: NodePath[]): NodePath[] {
  if (sink === 'exec' || sink === 'execSync') return args.slice(0, 1);
  const program = args[0]?.node;
  const viaShell =
    (program?.type === 'StringLiteral' && SHELLS.test(program.value)) ||
    args.some((a) => a.node?.type === 'ObjectExpression' && a.node.properties.some((p) =>
      p.type === 'ObjectProperty' && p.key.type === 'Identifier' && p.key.name === 'shell' &&
      p.value.type === 'BooleanLiteral' && p.value.value));
  return viaShell ? args.slice(0, 2) : args.slice(0, 1);
}
