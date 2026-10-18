/**
 * Tool-input → sink tracing for JavaScript MCP server source (MCP-005,
 * MCP-009). A sink call (`eval`, `Function`, `vm.run*`, child_process
 * `exec`/`spawn`/…, an `fs` call's path) is reported only when one of its arguments is derived from
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
import _traverse from '@babel/traverse';
import type { Binding, NodePath, Scope } from '@babel/traverse';
import type { Node } from '@babel/types';
import { parseJs, sourceChunks } from './js-parse.js';

const traverse = typeof _traverse === 'function' ? _traverse : (_traverse as { default: typeof _traverse }).default;

const NUMERIC_PROPERTIES = new Set(['length', 'size', 'byteLength']);
const NUMERIC_CALLS = /^(?:Number|parseInt|parseFloat|Math\.\w+|Date\.now)$/;

/** An expression whose value is a number, whatever its operands held. */
function yieldsNumber(path: NodePath): boolean {
  const n = path.node as Node;
  if (n.type === 'MemberExpression' && !n.computed && n.property.type === 'Identifier') {
    return NUMERIC_PROPERTIES.has(n.property.name);
  }
  if (n.type === 'CallExpression') {
    const c = n.callee;
    const name = c.type === 'Identifier' ? c.name
      : c.type === 'MemberExpression' && !c.computed && c.object.type === 'Identifier' && c.property.type === 'Identifier'
        ? `${c.object.name}.${c.property.name}` : '';
    return NUMERIC_CALLS.test(name);
  }
  return false;
}

export interface TaintedSink {
  line: number;
  snippet: string;
  /** Sink as written, e.g. `eval`, `child_process.exec`. */
  sink: string;
  /** How the argument reaches tool input, e.g. `format ← request`. */
  origin: string;
  /**
   * `code`/`process`: the input runs. `file-read`/`file-write`: it names the
   * file read or written; `file-meta`: the path listed, stat'ed or probed.
   */
  kind: SinkKind;
}

export type SinkKind = 'code' | 'process' | 'file-read' | 'file-write' | 'file-meta';

/**
 * Parameter names that mean tool/request input wherever they appear. Generic
 * names (`args`, `input`, `params`, `options`) are not on the list: a CLI's
 * `main(args)` spawning the command its operator configured is not
 * injection. Those parameters count only through a handler or a call site.
 */
const INPUT_NAMES = new Set(['req', 'request', 'tool_input', 'toolInput', 'tool_args', 'toolArgs']);

/** Methods whose function argument is an MCP tool/request handler. */
const HANDLER_REGISTRARS = new Set(['tool', 'registerTool', 'setRequestHandler', 'addTool']);

const CODE_SINKS = new Set(['eval', 'Function']);
const PROCESS_SINKS = new Set(['exec', 'execSync', 'spawn', 'spawnSync', 'execFile', 'execFileSync']);
const VM_SINKS = new Set(['runInNewContext', 'runInThisContext', 'runInContext', 'compileFunction']);
/** fs calls by what they do with their path argument(s). */
export const FS_CALLS: Record<string, { kind: 'file-read' | 'file-write' | 'file-meta'; paths: number }> = {
  ...Object.fromEntries(['readFile', 'readFileSync', 'createReadStream', 'open', 'openSync', 'readJson', 'readJsonSync']
    .map((n) => [n, { kind: 'file-read' as const, paths: 1 }])),
  ...Object.fromEntries(['writeFile', 'writeFileSync', 'appendFile', 'appendFileSync', 'createWriteStream', 'rm', 'rmSync',
    'rmdir', 'rmdirSync', 'unlink', 'unlinkSync', 'mkdir', 'mkdirSync', 'chmod', 'chmodSync', 'truncate', 'truncateSync',
    'outputFile', 'outputFileSync', 'writeJson', 'writeJsonSync', 'remove', 'removeSync']
    .map((n) => [n, { kind: 'file-write' as const, paths: 1 }])),
  ...Object.fromEntries(['rename', 'renameSync', 'copyFile', 'copyFileSync', 'cp', 'cpSync', 'symlink', 'symlinkSync', 'link', 'linkSync', 'copy', 'move']
    .map((n) => [n, { kind: 'file-write' as const, paths: 2 }])),
  ...Object.fromEntries(['readdir', 'readdirSync', 'opendir', 'opendirSync', 'stat', 'statSync', 'lstat', 'lstatSync',
    'access', 'accessSync', 'exists', 'existsSync', 'realpath', 'realpathSync', 'pathExists', 'pathExistsSync']
    .map((n) => [n, { kind: 'file-meta' as const, paths: 1 }])),
};
export const FS_MODULE = /^(?:node:)?fs(?:\/promises)?$|^(?:fs-extra|graceful-fs)$/;
const FS_NAMES = new Set(['fs', 'fsp', 'fsPromises', 'fse']);
const SHELLS = /^(?:\/(?:usr\/)?bin\/)?(?:sh|bash|zsh|dash|cmd(?:\.exe)?|powershell(?:\.exe)?|pwsh)$/i;
const CHILD_PROCESS_NAMES = new Set(['child_process', 'childProcess', 'cp']);

const MAX_DEPTH = 8;
const MAX_CACHED = 1_000;
const cache = new Map<string, TaintedSink[]>();

export function findTaintedSinks(code: string, filename = 'unknown.js'): TaintedSink[] {
  const key = `${filename}\0${createHash('sha1').update(code).digest('base64')}`;
  const cached = cache.get(key);
  if (cached) return cached.map((s) => ({ ...s }));
  const results = sourceChunks(code).flatMap((chunk) =>
    analyze(chunk.code).map((sink) => ({ ...sink, line: sink.line + chunk.startLine - 1 })),
  );
  if (cache.size >= MAX_CACHED) cache.delete(cache.keys().next().value!);
  cache.set(key, results);
  return results.map((s) => ({ ...s }));
}

/**
 * A string known without running the code: a literal, a template without
 * interpolations, `+` of such, or a never-reassigned constant holding one
 * (`const m = 'child_' + 'process'`). Bounded: a chain of constants is
 * followed a few steps.
 */
export function staticString(node: Node | null | undefined, scope?: Scope, depth = 0): string | undefined {
  if (!node || depth > 6) return undefined;
  switch (node.type) {
    case 'StringLiteral': return node.value;
    case 'TemplateLiteral':
      if (node.expressions.length === 0) return node.quasis[0]?.value.cooked ?? '';
      {
        let out = node.quasis[0]?.value.cooked ?? '';
        for (let i = 0; i < node.expressions.length; i++) {
          const part = staticString(node.expressions[i] as Node, scope, depth + 1);
          if (part === undefined) return undefined;
          out += part + (node.quasis[i + 1]?.value.cooked ?? '');
        }
        return out;
      }
    case 'BinaryExpression': {
      if (node.operator !== '+') return undefined;
      const l = staticString(node.left as Node, scope, depth + 1);
      const r = l === undefined ? undefined : staticString(node.right, scope, depth + 1);
      return r === undefined ? undefined : l! + r;
    }
    case 'Identifier': {
      const binding = scope?.getBinding(node.name);
      const decl = binding?.path.node;
      if (!binding?.constant || decl?.type !== 'VariableDeclarator' || decl.id.type !== 'Identifier') return undefined;
      return staticString(decl.init, binding.scope, depth + 1);
    }
    default: return undefined;
  }
}

/**
 * A call that loads a module by name: `require`, and the other handles on
 * the same loader (`module.require`, `process.mainModule.require`,
 * `require.main.require`, `createRequire(…)(…)`, `Module._load`).
 */
function isRequireCallee(callee: Node): boolean {
  if (callee.type === 'Identifier') return callee.name === 'require';
  if (callee.type === 'MemberExpression' && !callee.computed && callee.property.type === 'Identifier') {
    return callee.property.name === 'require' || callee.property.name === '_load';
  }
  return callee.type === 'CallExpression' && callee.callee.type === 'Identifier' && callee.callee.name === 'createRequire';
}

/** `require('m')` / `await import('m')` / `import('m')` → `m` (the name may be built from constants). */
function moduleOfInit(init: Node | null | undefined, scope?: Scope): string | undefined {
  if (!init) return undefined;
  if (init.type === 'AwaitExpression') return moduleOfInit(init.argument, scope);
  if (init.type === 'CallExpression') {
    const { callee, arguments: args } = init;
    if (isRequireCallee(callee) || callee.type === 'Import') return staticString(args[0] as Node, scope);
  }
  if (init.type === 'ImportExpression') return staticString(init.source, scope);
  return undefined;
}

/** A member's name when it is known: `o.name`, `o['name']`, `o[`name`]`. */
export function memberName(m: Node): string | undefined {
  if (m.type !== 'MemberExpression' && m.type !== 'OptionalMemberExpression') return undefined;
  if (!m.computed) return m.property.type === 'Identifier' ? m.property.name : undefined;
  const p = m.property;
  if (p.type === 'StringLiteral') return p.value;
  if (p.type === 'TemplateLiteral' && p.expressions.length === 0) return p.quasis[0]?.value.cooked ?? undefined;
  return undefined;
}

/** Module specifier a binding was imported/required from, if any. */
export function bindingModule(binding: Binding | undefined, depth = 0): string | undefined {
  if (!binding) return undefined;
  const parent = binding.path.parentPath?.node;
  if (parent?.type === 'ImportDeclaration') return parent.source.value;
  const node = binding.path.node;
  if (node.type !== 'VariableDeclarator') return undefined;
  const direct = moduleOfInit(node.init, binding.scope);
  if (direct !== undefined || depth > 3) return direct;
  // `const { exec } = cp` / `const proc = cp` where `cp = require('child_process')`
  if (node.init?.type === 'Identifier' && binding.constant) {
    return bindingModule(binding.scope.getBinding(node.init.name), depth + 1);
  }
  return undefined;
}

/**
 * The module export a local binding stands for: `exec` for `import { exec as
 * run }` or `const { exec: run } = require(…)`; `*` for a default/namespace
 * import or a whole-module `require`.
 */
function importedName(binding: Binding): string {
  const node = binding.path.node;
  if (node.type === 'ImportSpecifier') return node.imported.type === 'Identifier' ? node.imported.name : node.imported.value;
  if (node.type === 'VariableDeclarator' && node.id.type === 'ObjectPattern') {
    for (const prop of node.id.properties) {
      if (prop.type === 'ObjectProperty' && prop.value.type === 'Identifier' && prop.value.name === binding.identifier.name) {
        return prop.key.type === 'Identifier' ? prop.key.name : prop.key.type === 'StringLiteral' ? prop.key.value : '*';
      }
    }
  }
  return '*';
}

const CHILD_PROCESS_MODULE = /^(?:node:)?child_process$/;
const VM_MODULE = /^(?:node:)?vm$/;
/** execa's functions: `execa(file, args)`, `execaCommand("cmd line")`. */
const EXECA_FUNCTIONS: Record<string, 'program' | 'command'> = {
  execa: 'program', execaSync: 'program', execaNode: 'program', execaCommand: 'command', execaCommandSync: 'command',
};
const GLOBAL_OBJECTS = new Set(['globalThis', 'window', 'global', 'self']);

export interface SinkCallee {
  /** As written, e.g. `run (child_process.exec)`, `globalThis.eval`. */
  display: string;
  kind: 'code' | 'process';
  /** The underlying function, for argument selection: `exec`, `spawn`, `eval`, `execaCommand`. */
  fn: string;
}

/**
 * The command/code sink a call invokes, resolving how the server reached it:
 * aliased or destructured imports (`import { exec as run }`, `const {
 * execSync: sh } = require(…)`), a whole module under any name (`const proc
 * = require("child_process")`, `await import("child_process")`,
 * `require("child_process").execSync(…)`), execa and shelljs, and indirect
 * eval (`(0, eval)(code)`, `globalThis.eval(code)`).
 */
export function sinkCallee(path: NodePath): SinkCallee | undefined {
  if (!path.isCallExpression() && !path.isNewExpression()) return undefined;
  let callee = path.node.callee as Node;
  // (0, eval)(code): the last expression of a sequence is the callee.
  if (callee.type === 'SequenceExpression') callee = callee.expressions[callee.expressions.length - 1];

  if (callee.type === 'Identifier') {
    const name = callee.name;
    const binding = path.scope.getBinding(name);
    // `const exec = promisify(execFile)`: the function it wraps, not its name
    const wrapped = promisifiedSink(path, binding);
    if (wrapped) return { display: `${name} (promisify(${wrapped}))`, kind: 'process', fn: wrapped };
    const mod = bindingModule(binding);
    if (mod && binding) {
      const imported = importedName(binding);
      if (CHILD_PROCESS_MODULE.test(mod) && PROCESS_SINKS.has(imported)) {
        return { display: imported === name ? name : `${name} (child_process.${imported})`, kind: 'process', fn: imported };
      }
      if (mod === 'execa' && EXECA_FUNCTIONS[imported]) return { display: name, kind: 'process', fn: imported };
      return undefined;
    }
    // `const run = cp.exec` / `const run = require('child_process').exec`:
    // the function the alias was taken from
    const decl = binding?.path.node;
    if (binding?.constant && decl?.type === 'VariableDeclarator' && decl.init?.type === 'MemberExpression') {
      const target = memberSink(binding.path as NodePath, decl.init);
      return target ? { ...target, display: `${name} (${target.display})` } : undefined;
    }
    if (CODE_SINKS.has(name) && !binding) return { display: name, kind: 'code', fn: name };
    if (PROCESS_SINKS.has(name) && path.isCallExpression()) return { display: name, kind: 'process', fn: name };
    return undefined;
  }

  if (callee.type !== 'MemberExpression') return undefined;
  return memberSink(path, callee);
}

/**
 * The sink a member expression names — `cp.exec`, `require('child_process')['exec']`,
 * `process.mainModule.require('child_process').execSync`, `require('vm').runInThisContext`,
 * `vm.Script`, a module's `_compile`, the Function constructor reached through
 * any function's `constructor` (`[].constructor.constructor`).
 */
function memberSink(path: NodePath, callee: Node & { type: 'MemberExpression' }): SinkCallee | undefined {
  const prop = memberName(callee);
  if (prop === undefined) return undefined;
  const object = callee.object;
  if (prop === 'eval' && object.type === 'Identifier' && GLOBAL_OBJECTS.has(object.name)) {
    return { display: `${object.name}.eval`, kind: 'code', fn: 'eval' };
  }
  // Module.prototype._compile(source, filename): compiles and runs source as a module
  // (two arguments; a template engine's own `_compile()` takes none or one)
  const argc = (path.node as { arguments?: unknown[] }).arguments?.length ?? 0;
  if (prop === '_compile' && argc >= 2) return { display: '._compile', kind: 'code', fn: 'Function' };
  // `x.constructor.constructor(code)`, `(() => {}).constructor(code)`,
  // `Function.prototype.constructor(code)`: the Function constructor
  if (prop === 'constructor' && (
    memberName(object) === 'constructor'
    || (memberName(object) === 'prototype' && (object as { object?: Node }).object?.type === 'Identifier'
      && ((object as { object: Node & { name?: string } }).object.name === 'Function'))
    || object.type === 'ArrowFunctionExpression' || object.type === 'FunctionExpression'
    || (object.type === 'Identifier' && object.name === 'Function' && !path.scope.getBinding('Function'))
  )) {
    return { display: 'Function (via .constructor)', kind: 'code', fn: 'Function' };
  }
  // require("child_process").execSync(…) / (await import("child_process")).exec(…)
  const inline = moduleOfInit(object, path.scope);
  if (inline) {
    if (CHILD_PROCESS_MODULE.test(inline) && PROCESS_SINKS.has(prop)) return { display: `require("${inline}").${prop}`, kind: 'process', fn: prop };
    if (VM_MODULE.test(inline) && (VM_SINKS.has(prop) || prop === 'Script')) return { display: `require("${inline}").${prop}`, kind: 'code', fn: prop };
    return undefined;
  }
  if (object.type !== 'Identifier') return undefined;
  const mod = bindingModule(path.scope.getBinding(object.name));
  if (PROCESS_SINKS.has(prop) && (mod ? CHILD_PROCESS_MODULE.test(mod) : CHILD_PROCESS_NAMES.has(object.name))) {
    return { display: `${object.name}.${prop}`, kind: 'process', fn: prop };
  }
  if (mod === 'shelljs' && prop === 'exec') return { display: `${object.name}.exec`, kind: 'process', fn: 'exec' };
  if (mod === 'execa' && EXECA_FUNCTIONS[prop]) return { display: `${object.name}.${prop}`, kind: 'process', fn: prop };
  if ((VM_SINKS.has(prop) || prop === 'Script') && (mod ? VM_MODULE.test(mod) : object.name === 'vm')) {
    return { display: `${object.name}.${prop}`, kind: 'code', fn: prop };
  }
  return undefined;
}

/**
 * The child_process function a `promisify` wrapper binds: `execFile` for
 * `const exec = promisify(execFile)` or `util.promisify(cp.execFile)`. Its
 * own name says nothing — a promisified execFile named `exec` still starts
 * the program directly, without a shell.
 */
function promisifiedSink(path: NodePath, binding: Binding | undefined): string | undefined {
  const node = binding?.path.node;
  if (node?.type !== 'VariableDeclarator' || node.init?.type !== 'CallExpression') return undefined;
  const { callee, arguments: args } = node.init;
  const isPromisify = (callee.type === 'Identifier' && callee.name === 'promisify')
    || (callee.type === 'MemberExpression' && callee.property.type === 'Identifier' && callee.property.name === 'promisify');
  const target = args[0];
  if (!isPromisify || !target) return undefined;
  if (target.type === 'Identifier') {
    const tb = path.scope.getBinding(target.name);
    const mod = bindingModule(tb);
    const fn = mod && tb ? (CHILD_PROCESS_MODULE.test(mod) ? importedName(tb) : undefined) : target.name;
    return fn && PROCESS_SINKS.has(fn) ? fn : undefined;
  }
  if (target.type === 'MemberExpression' && target.property.type === 'Identifier' && PROCESS_SINKS.has(target.property.name)) {
    const obj = target.object;
    const mod = obj.type === 'Identifier' ? bindingModule(path.scope.getBinding(obj.name)) : moduleOfInit(obj);
    const childProcess = mod ? CHILD_PROCESS_MODULE.test(mod) : obj.type === 'Identifier' && CHILD_PROCESS_NAMES.has(obj.name);
    return childProcess ? target.property.name : undefined;
  }
  return undefined;
}

/**
 * Names whose every binding in the file is a never-reassigned literal
 * (`const query = "orders"`): whatever such a name is called, it holds no
 * caller input. A name bound anywhere else (a parameter, a destructured
 * argument, an assignment from a call) is left out.
 */
export function literalOnlyNames(code: string): Set<string> {
  const literal = new Set<string>();
  const other = new Set<string>();
  for (const chunk of sourceChunks(code)) {
    const ast = parseJs(chunk.code);
    if (!ast) continue;
    try {
      traverse(ast, {
        Scopable(path) {
          for (const [name, b] of Object.entries(path.scope.bindings)) {
            const node = b.path.node;
            const init = node.type === 'VariableDeclarator' && node.id.type === 'Identifier' ? node.init : undefined;
            const isLiteral = b.constant && !!init && (init.type === 'StringLiteral' || init.type === 'NumericLiteral'
              || init.type === 'BooleanLiteral' || (init.type === 'TemplateLiteral' && init.expressions.length === 0));
            (isLiteral ? literal : other).add(name);
          }
        },
      });
    } catch { /* deep AST: names stay unknown */ }
  }
  return new Set([...literal].filter((n) => !other.has(n)));
}

/** `fs`, `fsp`, `import { promises as fs } from 'fs'`, `fs.promises`. */
export function isFsObject(path: NodePath, object: Node): boolean {
  if (object.type === 'MemberExpression') {
    return object.property.type === 'Identifier' && object.property.name === 'promises' && isFsObject(path, object.object);
  }
  if (object.type !== 'Identifier') return false;
  const binding = path.scope.getBinding(object.name);
  const mod = bindingModule(binding);
  if (mod) return FS_MODULE.test(mod);
  return !binding && FS_NAMES.has(object.name);
}

/**
 * Evidence that the file confines caller-named paths to a base directory: a
 * path is resolved (`path.resolve`, `realpath`, `normalize`) and compared
 * against a base (`.startsWith(base)`, `path.relative`, an is-inside helper).
 * Same file-level rule as the Python analyzer.
 */
export function confinesPaths(code: string): boolean {
  const resolves = /\b(?:resolve|realpath(?:Sync)?|normalize)\s*\(/.test(code);
  const confines = /\.startsWith\s*\(\s*(?!["'`])|\bpath\.relative\s*\(|\bis(?:Path)?(?:Inside|Within|Subdir|SubPath)\w*\s*\(/i.test(code);
  return resolves && confines;
}

function analyze(code: string): TaintedSink[] {
  const ast = parseJs(code);
  if (!ast) return [];

  let lines: string[] | undefined;
  const lineText = (line: number): string => (lines ??= code.split('\n'))[line - 1]?.trim() ?? '';

  // Pass 1: functions registered as tool/request handlers — all their
  // parameters carry tool input.
  const handlers = new WeakSet<Node>();
  // Parameters (by position) of local functions that are called with tool input.
  const taintedParams = new WeakMap<Node, Set<number>>();
  const results: TaintedSink[] = [];

  try {
    traverse(ast, {
      CallExpression(path) {
        const { callee, arguments: args } = path.node;
        if (callee.type !== 'MemberExpression' || callee.property.type !== 'Identifier') return;
        if (!HANDLER_REGISTRARS.has(callee.property.name)) return;
        // Inline, by reference (`server.tool("t", "d", {}, handleIt)`), or
        // FastMCP-TS's `addTool({ name, execute })`.
        const addHandler = (node: Node | undefined): void => {
          const fn = functionNode(path, node);
          if (fn) handlers.add(fn);
        };
        for (const arg of args) {
          if (arg.type === 'ObjectExpression') {
            for (const prop of arg.properties) {
              const key = prop.type === 'ObjectProperty' || prop.type === 'ObjectMethod' ? prop.key : undefined;
              const name = key?.type === 'Identifier' ? key.name : key?.type === 'StringLiteral' ? key.value : '';
              if (name !== 'execute' && name !== 'handler') continue;
              addHandler(prop.type === 'ObjectMethod' ? prop : prop.type === 'ObjectProperty' ? prop.value : undefined);
            }
          } else {
            addHandler(arg);
          }
        }
      },
    });

    let memo = new Map<Binding, string | null>();

    const bindingOrigin = (binding: Binding, depth: number): string | undefined => {
      if (memo.has(binding)) return memo.get(binding) ?? undefined;
      memo.set(binding, null); // cycle guard
      let origin: string | undefined;
      const name = binding.identifier.name;

      if (binding.kind === 'param') {
        const fn = binding.scope.block;
        if (handlers.has(fn) || INPUT_NAMES.has(name)) {
          origin = name;
        } else if (fn.type.includes('Function') || fn.type === 'ClassMethod' || fn.type === 'ObjectMethod') {
          const params = (fn as { params?: Node[] }).params ?? [];
          const id = binding.identifier;
          const index = params.findIndex((p) => (p.start ?? -1) <= (id.start ?? 0) && (id.end ?? 0) <= (p.end ?? -1));
          if (index !== -1 && taintedParams.get(fn)?.has(index)) origin = `${name} ← caller`;
        }
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
      // A number derived from input (`actions.length`, `Number(x)`) can't
      // carry a path, a query or a command
      if (yieldsNumber(path)) return undefined;
      const local = localFunctionCall(path);
      if (local) return returnOrigin(local, depth);
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
        MemberExpression(m) { if (yieldsNumber(m)) m.skip(); },
        CallExpression(c) {
          if (found) return c.stop();
          if (yieldsNumber(c)) return c.skip();
          // A call to a function of this file carries input only through what
          // it returns, not because input was passed in
          const fn = localFunctionCall(c);
          if (fn) {
            found = returnOrigin(fn, depth);
            c.skip();
          }
        },
      });
      return found;
    };

    /** The function a call invokes, when it is declared in this file. */
    const localFunctionCall = (path: NodePath): NodePath | undefined => {
      if (!path.isCallExpression()) return undefined;
      const callee = path.get('callee');
      if (!callee.isIdentifier()) return undefined;
      const binding = path.scope.getBinding(callee.node.name);
      if (!binding) return undefined;
      if (binding.path.isFunctionDeclaration()) return binding.path;
      if (binding.path.isVariableDeclarator()) {
        const init = binding.path.get('init');
        if (init.isFunctionExpression() || init.isArrowFunctionExpression()) return init;
      }
      return undefined;
    };

    /** First tool-input origin among a local function's return values.
     *  Memoized per function: recomputing it at every call site was
     *  exponential in call depth (a 1 KB file of nested helpers stalled a scan). */
    const returnMemo = new Map<Node, string | null>();
    const returnOrigin = (fn: NodePath, depth: number): string | undefined => {
      if (depth >= MAX_DEPTH) return undefined;
      const known = returnMemo.get(fn.node);
      if (known !== undefined) return known ?? undefined;
      returnMemo.set(fn.node, null); // recursion through itself carries nothing new
      const origin = computeReturnOrigin(fn, depth);
      returnMemo.set(fn.node, origin ?? null);
      return origin;
    };
    const computeReturnOrigin = (fn: NodePath, depth: number): string | undefined => {
      const name = (fn.node as { id?: { name?: string } }).id?.name ?? 'function';
      if (fn.isArrowFunctionExpression() && !fn.get('body').isBlockStatement()) {
        const from = expressionOrigin(fn.get('body') as NodePath, depth + 1);
        return from ? `${name}() ← ${from}` : undefined;
      }
      let found: string | undefined;
      fn.traverse({
        Function(inner) { inner.skip(); },
        ReturnStatement(r) {
          if (found) return r.stop();
          const arg = r.get('argument');
          if (arg.node) found = expressionOrigin(arg as NodePath, depth + 1);
        },
      });
      return found ? `${name}() ← ${found}` : undefined;
    };

    const report = (path: NodePath<Node>, sink: string, candidates: NodePath[], kind: SinkKind): void => {
      for (const arg of candidates) {
        if (!arg.node) continue;
        const origin = expressionOrigin(arg, 0);
        if (origin) {
          const line = path.node.loc?.start.line ?? 0;
          results.push({ line, snippet: lineText(line).slice(0, 120), sink, origin, kind });
          return;
        }
      }
    };

    // Pass 1b: carry tool input into local functions through their call sites
    // (`this.getFolderSize(request.params.arguments)` taints `getFolderSize(args)`),
    // to a fixpoint — a few rounds covers handler → helper → helper chains.
    for (let round = 0; round < 4; round++) {
      let changed = false;
      memo = new Map();
      traverse(ast, {
        CallExpression(path) {
          const targets = localCallees(path);
          if (targets.length === 0) return;
          const args = path.get('arguments') as NodePath[];
          args.forEach((arg, index) => {
            if (!arg.node || !expressionOrigin(arg, 0)) return;
            for (const target of targets) {
              const set = taintedParams.get(target) ?? new Set<number>();
              if (!set.has(index)) {
                set.add(index);
                taintedParams.set(target, set);
                changed = true;
              }
            }
          });
        },
      });
      if (!changed) break;
    }
    memo = new Map();

    // Pass 2: sinks.
    traverse(ast, {
      'CallExpression|NewExpression'(path: NodePath) {
        if (!path.isCallExpression() && !path.isNewExpression()) return;
        const callee = path.node.callee;
        const args = path.get('arguments') as NodePath[];

        const exec = sinkCallee(path);
        if (exec) {
          return report(path, exec.display, exec.kind === 'code' ? args : processArgs(exec.fn, args), exec.kind);
        }

        if (callee.type === 'Identifier') {
          // `import { readFile } from 'fs/promises'`, `const { stat } = require('fs')`
          const fsCall = FS_CALLS[callee.name];
          if (fsCall && FS_MODULE.test(bindingModule(path.scope.getBinding(callee.name)) ?? '')) {
            return report(path, callee.name, args.slice(0, fsCall.paths), fsCall.kind);
          }
          return;
        }

        if (callee.type === 'MemberExpression' && callee.property.type === 'Identifier') {
          const prop = callee.property.name;
          const fsCall = FS_CALLS[prop];
          if (fsCall && isFsObject(path, callee.object)) {
            const shown = callee.object.type === 'Identifier' ? callee.object.name : 'fs.promises';
            return report(path, `${shown}.${prop}`, args.slice(0, fsCall.paths), fsCall.kind);
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
  if (sink === 'exec' || sink === 'execSync' || EXECA_FUNCTIONS[sink] === 'command') return args.slice(0, 1);
  const program = args[0]?.node;
  const viaShell =
    (program?.type === 'StringLiteral' && SHELLS.test(program.value)) ||
    args.some((a) => a.node?.type === 'ObjectExpression' && a.node.properties.some((p) =>
      p.type === 'ObjectProperty' && p.key.type === 'Identifier' && p.key.name === 'shell' &&
      p.value.type === 'BooleanLiteral' && p.value.value));
  return viaShell ? args.slice(0, 2) : args.slice(0, 1);
}

/** The function a handler argument is: inline, or a local function named by reference. */
function functionNode(path: NodePath, node: Node | undefined): Node | undefined {
  if (!node) return undefined;
  if (node.type === 'ArrowFunctionExpression' || node.type === 'FunctionExpression' || node.type === 'ObjectMethod') return node;
  if (node.type !== 'Identifier') return undefined;
  const target = path.scope.getBinding(node.name)?.path.node;
  if (target?.type === 'FunctionDeclaration') return target;
  if (target?.type === 'VariableDeclarator' && (target.init?.type === 'ArrowFunctionExpression' || target.init?.type === 'FunctionExpression')) {
    return target.init;
  }
  return undefined;
}

/**
 * Functions defined in this file that a call expression invokes: a function
 * declaration / function-valued variable called by name, or a method of the
 * enclosing class called through `this`.
 */
export function localCallees(path: NodePath): Node[] {
  if (!path.isCallExpression()) return [];
  const callee = path.node.callee;
  if (callee.type === 'Identifier') {
    const binding = path.scope.getBinding(callee.name);
    const node = binding?.path.node;
    if (!node) return [];
    if (node.type === 'FunctionDeclaration') return [node];
    if (node.type === 'VariableDeclarator' && (node.init?.type === 'ArrowFunctionExpression' || node.init?.type === 'FunctionExpression')) {
      return [node.init];
    }
    return [];
  }
  if (callee.type === 'MemberExpression' && callee.object.type === 'ThisExpression' && callee.property.type === 'Identifier') {
    const name = callee.property.name;
    const classBody = path.findParent((p) => p.isClassBody());
    if (!classBody?.isClassBody()) return [];
    return classBody.node.body.filter(
      (m) => (m.type === 'ClassMethod' || m.type === 'ClassPrivateMethod') && m.key.type === 'Identifier' && m.key.name === name,
    );
  }
  return [];
}
