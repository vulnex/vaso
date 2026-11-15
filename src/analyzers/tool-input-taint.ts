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

import { cutLine } from './finding-snippet.js';
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
  /** The whole line when `snippet` is a cut of it. */
  sourceLine?: string;
  /** Sink as written, e.g. `eval`, `child_process.exec`. */
  sink: string;
  /** How the argument reaches tool input, e.g. `format ← request`. */
  origin: string;
  /**
   * `code`/`process`: the input runs. `file-read`/`file-write`: it names the
   * file read or written; `file-meta`: the path listed, stat'ed or probed.
   */
  kind: SinkKind;
  /** `query`: every tainted interpolation stands for a whole statement (a derived table, `EXPLAIN`). */
  wrapsStatement?: boolean;
}

export type SinkKind = 'code' | 'process' | 'file-read' | 'file-write' | 'file-meta' | 'query';

/** Database calls whose first argument is SQL text (`db.query`, `db.prepare`, Prisma's `$queryRawUnsafe`, postgres.js `sql.unsafe`). */
const SQL_METHODS = new Set(['query', 'execute', 'raw', 'prepare', 'unsafe', '$queryRawUnsafe', '$executeRawUnsafe']);
/** Generic method names (sqlite's `db.run/all/get/exec`): only SQL written in capitals counts. */
const SQL_GENERIC_METHODS = new Set(['exec', 'run', 'all', 'get', 'each']);
const SQL_KEYWORDS = String.raw`\b(?:SELECT\b[\s\S]{0,2000}?\bFROM|INSERT\s+INTO|UPDATE\b[^;]{0,200}?\bSET|DELETE\s+FROM|DROP\s+TABLE|CREATE\s+TABLE|ALTER\s+TABLE)\b`;
const SQL_TEXT = new RegExp(SQL_KEYWORDS, 'i');
const SQL_TEXT_CAPS = new RegExp(SQL_KEYWORDS);
/** An interpolation that stands for a whole statement: `FROM (${q})`, `EXPLAIN ${q}`. */
const WRAP_BEFORE = /\b(?:FROM|JOIN|AS)\s*\(\s*$|\bEXPLAIN(?:\s+[A-Z]+)*\s+$/i;

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
  // Input fields each handler's schema limits to fixed choices or numbers (`z.enum`, `z.number`)
  const constrainedInputs = new WeakMap<Node, Set<string>>();
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
        const constrained = constrainedSchemaFields(args as Node[]);
        const addHandler = (node: Node | undefined): void => {
          const fn = functionNode(path, node);
          if (fn) handlers.add(fn);
          if (fn && constrained.size > 0) constrainedInputs.set(fn, constrained);
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

    /** A handler's input field its schema limits to fixed choices or numbers: `sort` from `{ sort }`, or `args.sort`. */
    const constrainedInput = (p: NodePath): boolean => {
      const param = (name: string): Binding | undefined => {
        const b = p.scope.getBinding(name);
        return b?.kind === 'param' && handlers.has(b.scope.block) ? b : undefined;
      };
      if (p.isIdentifier()) {
        const b = param(p.node.name);
        const field = b ? destructuredField(b) : undefined;
        return !!b && field !== undefined && !!constrainedInputs.get(b.scope.block)?.has(field);
      }
      if (p.isMemberExpression() && !p.node.computed && p.node.object.type === 'Identifier' && p.node.property.type === 'Identifier') {
        const b = param(p.node.object.name);
        const first = (b?.scope.block as { params?: Node[] } | undefined)?.params?.[0];
        return !!b && first === b.identifier && !!constrainedInputs.get(b.scope.block)?.has(p.node.property.name);
      }
      return false;
    };

    /** SQL text built from tool input and handed to `<shown>.<prop>(…)`. */
    const reportSql = (path: NodePath, prop: string, shown: string, args: NodePath[]): void => {
      if (!(SQL_METHODS.has(prop) || SQL_GENERIC_METHODS.has(prop)) || !args[0]) return;
      const built = sqlPieces(args[0], SQL_METHODS.has(prop) ? SQL_TEXT : SQL_TEXT_CAPS);
      if (!built) return;
      const tainted = built.parts.filter((p) => p.path.node && !sqlSafePiece(p.path, constrainedInput) && expressionOrigin(p.path, 0));
      if (tainted.length === 0) return;
      const origin = expressionOrigin(tainted[0].path, 0)!;
      const line = path.node.loc?.start.line ?? 0;
      results.push({
        line, ...cutLine(lineText(line)), sink: `${shown}.${prop}`, origin, kind: 'query',
        ...(tainted.every((p) => p.wraps) ? { wrapsStatement: true } : {}),
      });
    };

    const report = (path: NodePath<Node>, sink: string, candidates: NodePath[], kind: SinkKind): void => {
      for (const arg of candidates) {
        if (!arg.node) continue;
        const origin = expressionOrigin(arg, 0);
        if (origin) {
          const line = path.node.loc?.start.line ?? 0;
          results.push({ line, ...cutLine(lineText(line)), sink, origin, kind });
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
          // `const run = pool.query.bind(pool); run(`SELECT …${name}`)`
          const bound = boundSqlMethod(path.scope.getBinding(callee.name));
          if (bound) reportSql(path, bound.prop, bound.shown, args);
          return;
        }

        if (callee.type === 'MemberExpression' && callee.property.type === 'Identifier') {
          const prop = callee.property.name;
          const fsCall = FS_CALLS[prop];
          if (fsCall && isFsObject(path, callee.object)) {
            const shown = callee.object.type === 'Identifier' ? callee.object.name : 'fs.promises';
            return report(path, `${shown}.${prop}`, args.slice(0, fsCall.paths), fsCall.kind);
          }
          // SQL text built from tool input: `db.prepare(`SELECT … '${name}'`)`, `"… WHERE id = " + id`
          const shown = callee.object.type === 'Identifier' ? callee.object.name : callee.object.type === 'ThisExpression' ? 'this' : '…';
          reportSql(path, prop, shown, args);
        }
      },
    });
  } catch {
    // Pathological ASTs (errorRecovery output) — report what was found so far.
  }

  return results;
}

/**
 * The interpolated pieces of an SQL string an argument builds: an untagged
 * template literal, a `+` chain, `[…].join(sep)`, `"…".concat(…)` or
 * `util.format("…%s…", …)` whose literal text is SQL — given inline, through
 * a variable it was declared with (and `q += …` appends to it), or as what a
 * local helper returns. Tagged templates (sql`…`) are parameterized by their
 * library and are not text.
 */
function sqlPieces(arg: NodePath, sql: RegExp, depth = 0): { parts: Array<{ path: NodePath; wraps: boolean }> } | undefined {
  if (depth > 3) return undefined;
  const fromOperands = (operands: NodePath[], sep = ''): { parts: Array<{ path: NodePath; wraps: boolean }> } | undefined => {
    const text = operands.map((p) => staticString(p.node, p.scope) ?? ' ').join(sep || '');
    if (!sql.test(text)) return undefined;
    return { parts: operands.filter((p) => staticString(p.node, p.scope) === undefined).map((path) => ({ path, wraps: false })) };
  };
  if (arg.isTemplateLiteral()) {
    const quasis = arg.node.quasis.map((q) => q.value.cooked ?? q.value.raw);
    if (!sql.test(quasis.join(' '))) return undefined;
    const expressions = arg.get('expressions') as NodePath[];
    return {
      parts: expressions.map((path, i) => ({
        path,
        wraps: WRAP_BEFORE.test(quasis[i] ?? '') && /^\s*(?:\)|$)/.test(quasis[i + 1] ?? ''),
      })),
    };
  }
  if (arg.isBinaryExpression({ operator: '+' })) {
    const operands: NodePath[] = [];
    const flatten = (p: NodePath): void => {
      if (p.isBinaryExpression({ operator: '+' }) && operands.length < 64) {
        flatten(p.get('left') as NodePath);
        flatten(p.get('right') as NodePath);
      } else operands.push(p);
    };
    flatten(arg);
    return fromOperands(operands);
  }
  if (arg.isCallExpression()) {
    const callee = arg.get('callee');
    const args = arg.get('arguments') as NodePath[];
    if (callee.isMemberExpression() && !callee.node.computed && callee.node.property.type === 'Identifier') {
      const method = callee.node.property.name;
      const object = callee.get('object') as NodePath;
      // ["SELECT … '", name, "'"].join("")
      if (method === 'join' && object.isArrayExpression()) {
        const elements = (object.get('elements') as NodePath[]).filter((e) => e.node && !e.isSpreadElement());
        if (elements.length > 64) return undefined;
        return fromOperands(elements, args[0] ? staticString(args[0].node, args[0].scope) ?? ' ' : ',');
      }
      // "SELECT … '".concat(name, "'")
      if (method === 'concat' && staticString(object.node, object.scope) !== undefined) {
        return fromOperands([object, ...args].slice(0, 64));
      }
      // util.format("SELECT … '%s'", name)
      if (method === 'format' && object.isIdentifier() && (object.node.name === 'util' || bindingModule(object.scope.getBinding(object.node.name)) === 'util')) {
        return formatPieces(args, sql);
      }
    }
    if (callee.isIdentifier()) {
      const binding = arg.scope.getBinding(callee.node.name);
      if (callee.node.name === 'format' && bindingModule(binding) === 'util') return formatPieces(args, sql);
      // a local helper that returns the SQL text: `function byName(n) { return `…${n}…`; }`
      const returned = returnedExpression(binding);
      return returned ? sqlPieces(returned, sql, depth + 1) : undefined;
    }
    return undefined;
  }
  if (arg.isIdentifier()) {
    const binding = arg.scope.getBinding(arg.node.name);
    if (!binding?.path.isVariableDeclarator()) return undefined;
    const init = binding.path.get('init');
    if (!init.node) return undefined;
    if (binding.constant) return sqlPieces(init as NodePath, sql, depth + 1);
    // `let q = "SELECT …"; q += " WHERE name = '" + name + "'"`: the text is the declaration plus every append
    const appends = binding.constantViolations;
    if (appends.length === 0 || appends.length > 16) return undefined;
    const operands: NodePath[] = [init as NodePath];
    for (const v of appends) {
      if (!v.isAssignmentExpression({ operator: '+=' })) return undefined;
      const right = v.get('right') as NodePath;
      const flatten = (p: NodePath): void => {
        if (p.isBinaryExpression({ operator: '+' }) && operands.length < 64) {
          flatten(p.get('left') as NodePath);
          flatten(p.get('right') as NodePath);
        } else operands.push(p);
      };
      flatten(right);
    }
    const templates = operands.filter((p) => p.isTemplateLiteral());
    const text =operands.map((p) => (p.isTemplateLiteral() ? p.node.quasis.map((q) => q.value.cooked ?? '').join(' ') : staticString(p.node, p.scope) ?? ' ')).join('');
    if (!sql.test(text)) return undefined;
    return {
      parts: [
        ...operands.filter((p) => !p.isTemplateLiteral() && staticString(p.node, p.scope) === undefined).map((path) => ({ path, wraps: false })),
        ...templates.flatMap((t) => (t.get('expressions') as NodePath[]).map((path) => ({ path, wraps: false }))),
      ],
    };
  }
  return undefined;
}

/** `format("SELECT … '%s'", a, b)`: the arguments after a format string that is SQL. */
function formatPieces(args: NodePath[], sql: RegExp): { parts: Array<{ path: NodePath; wraps: boolean }> } | undefined {
  const text = args[0] ? staticString(args[0].node, args[0].scope) : undefined;
  if (text === undefined || !sql.test(text)) return undefined;
  return { parts: args.slice(1).map((path) => ({ path, wraps: false })) };
}

/** What a local function returns, when it is one expression (an arrow body or a single `return`). */
function returnedExpression(binding: Binding | undefined): NodePath | undefined {
  if (!binding) return undefined;
  let fn: NodePath | undefined;
  if (binding.path.isFunctionDeclaration()) fn = binding.path;
  else if (binding.path.isVariableDeclarator()) {
    const init = binding.path.get('init');
    if (init.isFunctionExpression() || init.isArrowFunctionExpression()) fn = init as NodePath;
  }
  if (!fn) return undefined;
  const body = fn.get('body') as NodePath;
  if (!body.isBlockStatement()) return body;
  const statements = body.get('body') as NodePath[];
  const returns = statements.filter((s) => s.isReturnStatement());
  if (returns.length !== 1) return undefined;
  const argument = returns[0].get('argument') as NodePath;
  return argument.node ? argument : undefined;
}

/** `X.query.bind(X)` held in a constant: the SQL method it calls. */
function boundSqlMethod(binding: Binding | undefined): { prop: string; shown: string } | undefined {
  const decl = binding?.constant ? binding.path.node : undefined;
  const init = decl?.type === 'VariableDeclarator' ? decl.init : undefined;
  if (init?.type !== 'CallExpression' || init.callee.type !== 'MemberExpression' || init.callee.property.type !== 'Identifier'
    || init.callee.property.name !== 'bind') return undefined;
  const target = init.callee.object;
  if (target.type !== 'MemberExpression' || target.property.type !== 'Identifier' || !SQL_METHODS.has(target.property.name)) return undefined;
  return { prop: target.property.name, shown: target.object.type === 'Identifier' ? target.object.name : '…' };
}

/** Calls that make a value safe to put in SQL text: driver escaping and identifier/literal quoting. */
const SQL_ESCAPES = /^(?:escape|escapeId|escapeIdentifier|escapeLiteral|escapeString|quoteIdent|quoteIdentifier|quoteLiteral|quote_ident|quote_literal)$/;
/** Modules whose `format` escapes its values (`mysql.format`, pg-format's `format('%I', x)`). */
const SQL_FORMAT_MODULES = /^(?:mysql2?(?:\/promise)?|sqlstring|pg-format)$/;
/** SQL drivers and builders whose escaping helpers SQL_ESCAPES names. */
const SQL_ESCAPE_MODULES = /^(?:mysql2?(?:\/promise)?|sqlstring|pg|pg-format|pg-escape|knex)$/;

/** The root identifier of `a.b.c(…).d`, `new a.B()`, `await a.connect()`. */
function rootIdentifier(node: Node | null | undefined): Node | undefined {
  let n = node;
  for (let i = 0; n && i < 32; i++) {
    if (n.type === 'Identifier' || n.type === 'ThisExpression') return n;
    if (n.type === 'AwaitExpression') n = n.argument;
    else if (n.type === 'MemberExpression' || n.type === 'OptionalMemberExpression') n = n.object;
    else if (n.type === 'CallExpression' || n.type === 'OptionalCallExpression' || n.type === 'NewExpression') n = n.callee as Node;
    else if (n.type === 'TSNonNullExpression' || n.type === 'TSAsExpression' || n.type === 'ParenthesizedExpression') n = n.expression;
    else return undefined;
  }
  return undefined;
}

/**
 * Whether the receiver of an escaping call can be a SQL driver: `mysql`,
 * `pg`, a connection or pool made from one (`await mysql.createConnection()`,
 * `new pg.Pool()`, `pool.connect()`), or one the code doesn't show (a
 * parameter, `this.db`, a global). A local object, function or class is not.
 */
function sqlDriverReceiver(node: Node, scope: Scope, depth = 0): boolean {
  if (depth > 4) return false;
  const root = rootIdentifier(node);
  if (!root) return false;
  if (root.type === 'ThisExpression') return true;
  if (root.type !== 'Identifier') return false;
  const binding = scope.getBinding(root.name);
  if (!binding || binding.kind === 'param') return true;
  const module = bindingModule(binding);
  if (module !== undefined) return SQL_ESCAPE_MODULES.test(module);
  const decl = binding.path.node;
  if (decl.type !== 'VariableDeclarator' || !decl.init) return false;
  return decl.init !== node && sqlDriverReceiver(decl.init, binding.scope, depth + 1);
}

/** `mysql.escape(x)`, `conn.escape(x)`, `import { escape } from "sqlstring"` — not a local `escape` or the global URL encoder. */
function sqlEscapeCall(callee: NodePath): boolean {
  if (callee.isIdentifier()) {
    const module = bindingModule(callee.scope.getBinding(callee.node.name));
    return module !== undefined && SQL_ESCAPE_MODULES.test(module);
  }
  return callee.isMemberExpression() && sqlDriverReceiver(callee.node.object, callee.scope);
}

/**
 * An interpolated piece that can't carry SQL whatever the input: an escaped
 * value (`mysql.escape(x)`, `pg.escapeIdentifier(x)`), a placeholder list
 * (`ids.map(() => "?").join(",")`, `.map((_, i) => `$${i + 1}`)`), a choice
 * from fixed values (`[…].includes(x) ? x : "id"`), or input the tool's schema
 * limits to fixed values or numbers (`z.enum([...])`, `z.number()`).
 */
function sqlSafePiece(path: NodePath, constrained: (path: NodePath) => boolean, depth = 0): boolean {
  if (depth > 4 || !path.node) return false;
  if (constrained(path)) return true;
  if (path.isIdentifier()) {
    const binding = path.scope.getBinding(path.node.name);
    if (!binding?.constant || !binding.path.isVariableDeclarator()) return false;
    const init = binding.path.get('init') as NodePath;
    return !!init.node && sqlSafePiece(init, constrained, depth + 1);
  }
  if (path.isConditionalExpression()) return allowListChoice(path);
  // `COLUMNS[name] ?? "id"`: a lookup in a table of fixed values, with a fixed fallback
  if (path.isLogicalExpression() && (path.node.operator === '??' || path.node.operator === '||')) {
    const fixedOr = (p: NodePath): boolean => staticString(p.node, p.scope) !== undefined || p.isNumericLiteral() || sqlSafePiece(p, constrained, depth + 1);
    return fixedOr(path.get('left') as NodePath) && fixedOr(path.get('right') as NodePath);
  }
  if (path.isMemberExpression() && path.node.computed) return fixedList(path.node.object, path.scope, 0, true);
  if (path.isTemplateLiteral()) {
    return (path.get('expressions') as NodePath[]).every((e) => sqlSafePiece(e, constrained, depth + 1));
  }
  if (!path.isCallExpression()) return false;
  const callee = path.get('callee');
  const name = callee.isIdentifier() ? callee.node.name
    : callee.isMemberExpression() && !callee.node.computed && callee.node.property.type === 'Identifier' ? callee.node.property.name : '';
  if (SQL_ESCAPES.test(name) && sqlEscapeCall(callee as NodePath)) return true;
  if (name === 'format') {
    const holder = callee.isIdentifier() ? callee : callee.isMemberExpression() ? callee.get('object') as NodePath : undefined;
    if (holder?.isIdentifier() && SQL_FORMAT_MODULES.test(bindingModule(holder.scope.getBinding(holder.node.name)) ?? holder.node.name)) return true;
  }
  if (callee.isMemberExpression() && (name === 'join' || name === 'map')) {
    const receiver = callee.get('object') as NodePath;
    const mapped = name === 'join' ? receiver : path;
    if (name === 'join') {
      // the separator is SQL text too: absent or fixed
      const sep = (path.get('arguments') as NodePath[])[0];
      if (sep && staticString(sep.node, sep.scope) === undefined) return false;
    }
    return mapped.isCallExpression() && placeholderMap(mapped);
  }
  return false;
}

/** `xs.map(() => "?")`, `xs.map((_, i) => `$${i + 1}`)`: every element replaced by text that ignores it. */
function placeholderMap(call: NodePath): boolean {
  if (!call.isCallExpression()) return false;
  const callee = call.node.callee;
  if (callee.type !== 'MemberExpression' || callee.property.type !== 'Identifier' || callee.property.name !== 'map') return false;
  const cb = (call.get('arguments') as NodePath[])[0];
  if (!cb || !(cb.isArrowFunctionExpression() || cb.isFunctionExpression())) return false;
  const params = cb.node.params;
  if (params.some((p) => p.type !== 'Identifier')) return false;
  const element = params[0]?.type === 'Identifier' ? params[0].name : undefined;
  const index = params[1]?.type === 'Identifier' ? params[1].name : undefined;
  const body = cb.get('body') as NodePath;
  if (!body.isExpression()) return false;
  // the body is literal text, numbers and the index only
  let ok = true;
  body.traverse({
    Identifier(id) {
      if (!id.isReferencedIdentifier()) return;
      if (id.node.name === element || id.node.name !== index) { ok = false; id.stop(); }
    },
    CallExpression(c) { ok = false; c.stop(); },
  });
  if (body.isIdentifier()) ok = body.node.name === index;
  return ok;
}

/** `ALLOWED.includes(x) ? x : "id"`, `x === "asc" ? "ASC" : "DESC"`: the value is one of fixed choices. */
function allowListChoice(path: NodePath): boolean {
  if (!path.isConditionalExpression()) return false;
  let test = path.get('test') as NodePath;
  // `!ALLOWED.includes(x) ? "id" : x`: the value is checked in the other branch
  let negated = false;
  while (test.isUnaryExpression({ operator: '!' })) {
    negated = !negated;
    test = test.get('argument') as NodePath;
  }
  let checked: string | undefined;
  if (test.isCallExpression()) {
    const callee = test.node.callee;
    const first = test.node.arguments[0];
    if (callee.type === 'MemberExpression' && callee.property.type === 'Identifier' && /^(?:includes|has)$/.test(callee.property.name)
      && first?.type === 'Identifier' && fixedList(callee.object, test.scope)) {
      checked = first.name;
    }
  } else if (test.isBinaryExpression() && /^(?:===|==|!==|!=)$/.test(test.node.operator)) {
    if (test.node.operator.startsWith('!')) negated = !negated;
    const { left, right } = test.node;
    if (left.type === 'Identifier' && staticString(right, test.scope) !== undefined) checked = left.name;
    else if (right.type === 'Identifier' && staticString(left, test.scope) !== undefined) checked = right.name;
  } else if (test.isBinaryExpression({ operator: "in" }) && test.node.left.type === "Identifier" && fixedList(test.node.right, test.scope)) {
    checked = test.node.left.name;
  }
  // the checked value is one of the fixed choices only in the branch where the test holds
  const fixed = (branch: Node, holds: boolean): boolean =>
    staticString(branch, path.scope) !== undefined || branch.type === 'NumericLiteral'
    || (holds && checked !== undefined && branch.type === 'Identifier' && branch.name === checked);
  return fixed(path.node.consequent, !negated) && fixed(path.node.alternate, negated);
}

/** A list of fixed values: an array literal of strings/numbers, `new Set([...])` of them, an object literal (with `values`: of fixed values too), or a constant holding one. */
function fixedList(node: Node, scope: Scope, depth = 0, values = false): boolean {
  if (depth > 3) return false;
  if (node.type === 'ArrayExpression') {
    return node.elements.every((e) => !!e && (e.type === 'NumericLiteral' || (e.type !== 'SpreadElement' && staticString(e, scope) !== undefined)));
  }
  if (node.type === 'NewExpression' && node.callee.type === 'Identifier' && node.callee.name === 'Set') {
    const first = node.arguments[0];
    return !!first && first.type !== 'SpreadElement' && first.type !== 'ArgumentPlaceholder' && fixedList(first as Node, scope, depth + 1, values);
  }
  if (node.type === 'ObjectExpression') {
    return node.properties.every((p) => p.type === 'ObjectProperty' && !p.computed
      && (!values || p.value.type === 'NumericLiteral' || staticString(p.value as Node, scope) !== undefined));
  }
  if (node.type === 'Identifier') {
    const binding = scope.getBinding(node.name);
    const decl = binding?.path.node;
    if (!binding?.constant || decl?.type !== 'VariableDeclarator' || !decl.init) return false;
    return fixedList(decl.init, binding.scope, depth + 1, values);
  }
  return false;
}

/** zod refinements that keep a field's type (`z.enum([...]).optional()`). */
const ZOD_KEEPS_TYPE = new Set(['optional', 'default', 'describe', 'nullable', 'nullish', 'int', 'min', 'max', 'gt', 'gte', 'lt', 'lte',
  'positive', 'negative', 'nonnegative', 'nonpositive', 'finite', 'safe', 'catch', 'readonly', 'multipleOf', 'step', 'brand']);
/** zod types whose values are fixed choices or numbers. */
const ZOD_FIXED = new Set(['enum', 'nativeEnum', 'literal', 'number', 'boolean', 'bigint', 'int', 'nan']);

/** A schema field whose value can only be one of fixed choices, a number or a boolean (or an array of those). */
function fixedZodType(node: Node | null | undefined, depth = 0): boolean {
  let n = node;
  for (let i = 0; i < 16 && n?.type === 'CallExpression' && n.callee.type === 'MemberExpression' && n.callee.property.type === 'Identifier'
    && ZOD_KEEPS_TYPE.has(n.callee.property.name); i++) n = n.callee.object;
  if (n?.type !== 'CallExpression' || n.callee.type !== 'MemberExpression' || n.callee.property.type !== 'Identifier') return false;
  const kind = n.callee.property.name;
  if (ZOD_FIXED.has(kind)) return true;
  if (kind === 'array' && depth < 2) return fixedZodType(n.arguments[0] as Node, depth + 1);
  return false;
}

/**
 * Input fields a tool's schema limits to fixed choices or numbers: the shape
 * object (`server.tool(n, d, { sort: z.enum([...]) }, h)`), or its
 * `inputSchema`/`parameters`/`schema` given as a shape or `z.object({...})`.
 */
function constrainedSchemaFields(args: Node[]): Set<string> {
  const out = new Set<string>();
  const shapeOf = (node: Node | null | undefined): Node | undefined => {
    if (node?.type === 'ObjectExpression') return node;
    if (node?.type === 'CallExpression' && node.callee.type === 'MemberExpression' && node.callee.property.type === 'Identifier'
      && node.callee.property.name === 'object') return node.arguments[0]?.type === 'ObjectExpression' ? node.arguments[0] : undefined;
    return undefined;
  };
  const readShape = (shape: Node | undefined): void => {
    if (shape?.type !== 'ObjectExpression') return;
    for (const p of shape.properties) {
      if (p.type !== 'ObjectProperty' || p.computed) continue;
      const key = p.key.type === 'Identifier' ? p.key.name : p.key.type === 'StringLiteral' ? p.key.value : undefined;
      if (key && fixedZodType(p.value as Node)) out.add(key);
    }
  };
  for (const arg of args) {
    if (arg.type !== 'ObjectExpression') continue;
    const nested = arg.properties.find((p) => p.type === 'ObjectProperty' && !p.computed && p.key.type === 'Identifier'
      && /^(?:inputSchema|parameters|schema|argsSchema)$/.test(p.key.name));
    readShape(nested?.type === 'ObjectProperty' ? shapeOf(nested.value as Node) : arg);
  }
  return out;
}

/** The input field a handler parameter binding reads: `{ sort }` / `{ sort: s }` → `sort`. */
function destructuredField(binding: Binding): string | undefined {
  const fn = binding.scope.block as { params?: Node[] };
  const first = fn.params?.[0];
  if (first?.type !== 'ObjectPattern') return undefined;
  for (const p of first.properties) {
    if (p.type !== 'ObjectProperty' || p.computed) continue;
    const value = p.value.type === 'AssignmentPattern' ? p.value.left : p.value;
    if (value === binding.identifier) return p.key.type === 'Identifier' ? p.key.name : p.key.type === 'StringLiteral' ? p.key.value : undefined;
  }
  return undefined;
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
