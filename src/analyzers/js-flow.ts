/**
 * Value-following data flow for skill code (SKL-001), beyond the direct
 * `const d = readFileSync(p); fetch(url, { body: d })` the main analyzer
 * matches by name. A value read from a file or the environment is followed
 * through what code does to it before sending:
 *
 *  - `await` and promise/callback delivery (`readFile(p).then(d => …)`,
 *    `fs.readFile(p, (err, d) => …)`, a read stream's `data` events);
 *  - transformation and wrapping (`Buffer.from(d).toString('base64')`,
 *    `JSON.stringify({ d })`, templates, concatenation);
 *  - destructuring and filtering of `process.env`
 *    (`const { AWS_SECRET_ACCESS_KEY } = process.env`,
 *    `Object.entries(process.env).filter(…)`);
 *  - a parameter of a helper function of the same file that sends it, and —
 *    through `tainted-call` / `param-sink` records the skill check joins — of
 *    a helper module of the same skill;
 *  - sends through an alias (`const send = globalThis.fetch`), a client built
 *    by a network module (`axios.create()`, `https.request()`), and DNS
 *    queries whose name carries the data.
 *
 * Where a file read's path can be worked out statically (`path.join(os.homedir(),
 * '.ssh', 'id_rsa')`, a constant, the argument at the function's call sites) it
 * is classified: a credential store, a file outside the skill and workspace,
 * the skill's own file, a workspace file, or a path chosen at runtime.
 *
 * Every walk is bounded (expression depth, binding memo, call-site count,
 * helper rounds), so analysis stays linear in file size.
 */

import type { Binding, NodePath, Scope } from '@babel/traverse';
import type { Node } from '@babel/types';
import _traverse from '@babel/traverse';
import { bindingModule, memberName, staticString } from './tool-input-taint.js';
import { isCredentialPath } from './sensitive-paths.js';
import type { JsAst } from './js-parse.js';

const traverse = typeof _traverse === 'function' ? _traverse : (_traverse as { default: typeof _traverse }).default;

/** Where a file a skill reads lives, as far as its path can be worked out statically. */
export type SourcePath = 'credential' | 'outside' | 'own' | 'workspace' | 'runtime';

export interface Taint {
  kind: 'file' | 'env' | 'host' | 'param';
  /** What was read, as written: `readFile(~/.ssh/id_rsa)`, `process.env`, `process.env.TOKEN`. */
  origin: string;
  path?: SourcePath;
  /** file: the path as resolved (`~/.ssh/id_rsa`, `<skill>/template.txt`). */
  resolved?: string;
  /** env: the whole environment (or a filtered copy of it), not one value. */
  wholeEnv?: boolean;
  /** env: the one variable read. */
  envName?: string;
  /** param: the function and parameter position the value comes in through. */
  fn?: Node;
  index?: number;
}

export interface FlowRecord {
  line: number;
  /** Variable carrying the value at the send, else the source as written. */
  source: string;
  taint: Taint;
  sink: string;
  sinkObject?: string;
  /** Through a helper of this file: its name. */
  via?: string;
  dns?: boolean;
}

/** A call into a helper module of the skill (`require('./lib/upload')(d)`) carrying a read value. */
export interface ModuleCallRecord {
  line: number;
  module: string;
  exportName: string;
  argIndex: number;
  source: string;
  taint: Taint;
}

/** An exported function whose parameter reaches a send. */
export interface ParamSinkRecord {
  exportName: string;
  paramIndex: number;
  sink: string;
  line: number;
}

export interface FlowAnalysis {
  flows: FlowRecord[];
  moduleCalls: ModuleCallRecord[];
  paramSinks: ParamSinkRecord[];
  /** Reads of a credential store whose path is built, not written out (`path.join(os.homedir(), '.ssh', …)`). */
  credentialReads: Array<{ line: number; resolved: string }>;
  /** The file read each variable holds, by name (for flows the name-matching analyzer found). */
  namedReads: Map<string, Taint>;
}

const MAX_DEPTH = 12;
const MAX_CALL_SITES = 16;
const HELPER_ROUNDS = 4;

const READ_FUNCTIONS = new Set(['readFile', 'readFileSync', 'createReadStream', 'readJson', 'readJsonSync']);
const NET_MODULE = /^(?:node:)?(?:http|https|http2|net|tls|dgram)$|^(?:axios|got|ky|undici|node-fetch|cross-fetch|isomorphic-fetch|request|superagent|needle|phin|ws|socket\.io-client)$/;
const DNS_MODULE = /^(?:node:)?dns(?:\/promises)?$/;
const FETCH_MODULE = /^(?:node-fetch|cross-fetch|isomorphic-fetch|undici)$/;
/** Names network code is conventionally bound to, when the binding can't be resolved. */
const NET_NAMES = new Set(['http', 'https', 'net', 'tls', 'dgram', 'axios', 'got', 'superagent', 'needle']);
const GLOBAL_OBJECTS = new Set(['globalThis', 'window', 'global', 'self']);
const SEND_METHODS = new Set(['request', 'get', 'post', 'put', 'patch', 'send', 'write', 'end']);
const DNS_METHODS = /^(?:lookup|lookupService|resolve\w*|reverse)$/;
/** Calls whose result is a number or a boolean, whatever their arguments held. */
const SCALAR_METHODS = new Set(['length', 'size', 'byteLength', 'includes', 'startsWith', 'endsWith', 'indexOf', 'lastIndexOf', 'test', 'has', 'some', 'every', 'localeCompare']);
const SCALAR_CALLS = /^(?:Number|parseInt|parseFloat|Boolean|isNaN|Math\.\w+|Date\.now|Buffer\.byteLength|Array\.isArray)$/;
/** Calls that copy, reshape or encode their argument (the environment passes through these only). */
const ENV_COPY_CALLS = /^(?:JSON\.stringify|Object\.(?:entries|fromEntries|assign|keys|values)|structuredClone|Buffer\.from|String|encodeURIComponent|encodeURI|escape|btoa|\.(?:concat|join|map|filter|reduce|slice|toString|replace|stringify|encode|digest|update))$/;
/** Host identity — data only when it leaves through a DNS query name. */
const HOST_CALLS = new Set(['hostname', 'userInfo', 'networkInterfaces']);

/** Rank: the most serious taint a value carries is the one reported. */
function rank(t: Taint): number {
  if (t.kind === 'file') return t.path === 'credential' ? 9 : t.path === 'outside' ? 6 : 3;
  if (t.kind === 'env') return t.wholeEnv ? 8 : 7;
  if (t.kind === 'host') return 2;
  return 1;
}

function best(ts: Taint[]): Taint | undefined {
  let top: Taint | undefined;
  for (const t of ts) if (!top || rank(t) > rank(top)) top = t;
  return top;
}

function calleeText(callee: Node): string {
  if (callee.type === 'Identifier') return callee.name;
  if (callee.type === 'MemberExpression') {
    const prop = memberName(callee) ?? '';
    const obj = callee.object.type === 'Identifier' ? callee.object.name : '';
    return obj ? `${obj}.${prop}` : `.${prop}`;
  }
  return '';
}

function isProcessEnv(n: Node): boolean {
  return (n.type === 'MemberExpression' || n.type === 'OptionalMemberExpression') && memberName(n) === 'env'
    && n.object.type === 'Identifier' && n.object.name === 'process';
}

/** `os.homedir()`, `homedir()` (imported), `require('os').homedir()`, `process.env.HOME`. */
function isHomeDir(n: Node, scope: Scope): boolean {
  if ((n.type === 'MemberExpression' || n.type === 'OptionalMemberExpression') && isProcessEnv(n.object)) {
    return /^(?:HOME|USERPROFILE)$/.test(memberName(n) ?? '');
  }
  if (n.type !== 'CallExpression') return false;
  const c = n.callee;
  if (c.type === 'Identifier') return c.name === 'homedir' && /^(?:node:)?os$/.test(bindingModule(scope.getBinding('homedir')) ?? 'os');
  return c.type === 'MemberExpression' && memberName(c) === 'homedir';
}

function isPathCall(n: Node, scope: Scope, names: RegExp): string | undefined {
  if (n.type !== 'CallExpression') return undefined;
  const c = n.callee;
  if (c.type === 'MemberExpression') {
    const fn = memberName(c) ?? '';
    if (!names.test(fn)) return undefined;
    const o = c.object;
    if (o.type === 'Identifier') {
      const mod = bindingModule(scope.getBinding(o.name));
      if (mod ? /^(?:node:)?path(?:\/posix)?$/.test(mod) : o.name === 'path') return fn;
    }
    if (o.type === 'CallExpression' && o.callee.type === 'Identifier' && o.callee.name === 'require') return fn;
    return undefined;
  }
  if (c.type === 'Identifier' && names.test(c.name)) {
    const mod = bindingModule(scope.getBinding(c.name));
    return mod && /^(?:node:)?(?:path|url)$/.test(mod) ? c.name : undefined;
  }
  return undefined;
}

/** `import.meta.url` / `import.meta.dirname` / `import.meta.filename`. */
function importMeta(n: Node): string | undefined {
  if (n.type !== 'MemberExpression' || n.object.type !== 'MetaProperty') return undefined;
  return memberName(n);
}

/** Collapse `.` and `..` segments; `..` above the skill's own directory leaves it. */
function normalizePath(p: string): string {
  const parts = p.split('/');
  const out: string[] = [];
  for (const part of parts) {
    if (part === '.' || (part === '' && out.length > 0)) continue;
    if (part === '..') {
      const last = out[out.length - 1];
      if (last === '<skill>') out[out.length - 1] = '*';
      else if (last !== undefined && last !== '' && last !== '~' && last !== '*' && last !== '<cwd>') out.pop();
      else out.push('..');
      continue;
    }
    out.push(part);
  }
  return out.join('/') || '.';
}

export function classifyPath(resolved: string): SourcePath {
  const p = normalizePath(resolved);
  if (p.startsWith('<skill>')) return 'own';
  if (isCredentialPath(p.replace(/^~(?=\/|$)/, '/home/user').replace(/^<cwd>/, ''))) return 'credential';
  if (/^(?:~|\/(?!tmp\/|var\/folders\/|dev\/std|proc\/self\/))/.test(p)) return 'outside';
  if (p === '*' || p.startsWith('*')) return 'runtime';
  return 'workspace';
}

export function analyzeFlows(ast: JsAst): FlowAnalysis {
  const flows: FlowRecord[] = [];
  const moduleCalls: ModuleCallRecord[] = [];
  const paramSinks: ParamSinkRecord[] = [];
  const credentialReads: Array<{ line: number; resolved: string }> = [];
  const namedReads = new Map<string, Taint>();

  const bindingMemo = new Map<Binding, Taint[]>();
  const pathMemo = new Map<Binding, string[]>();
  const receiverMemo = new Map<Binding, 'net' | 'dns' | 'fetch' | undefined>();

  // ---- static paths -------------------------------------------------------

  /** Candidate values of a path expression; `*` stands for what can't be known. */
  const pathValues = (n: Node | null | undefined, scope: Scope, depth: number): string[] => {
    if (!n || depth > MAX_DEPTH) return ['*'];
    const s = staticString(n, scope);
    if (s !== undefined) return [s];
    if (n.type === 'Identifier') {
      if (n.name === '__dirname' && !scope.getBinding(n.name)) return ['<skill>'];
      if (n.name === '__filename' && !scope.getBinding(n.name)) return ['<skill>/file'];
      const b = scope.getBinding(n.name);
      return b ? bindingPaths(b, depth + 1) : ['*'];
    }
    if (isHomeDir(n, scope)) return ['~'];
    const meta = importMeta(n);
    if (meta) return meta === 'dirname' ? ['<skill>'] : ['<skill>/file'];
    if (n.type === 'TemplateLiteral') {
      let acc = [n.quasis[0]?.value.cooked ?? ''];
      n.expressions.forEach((e, i) => {
        const vals = pathValues(e as Node, scope, depth + 1);
        acc = acc.flatMap(a => vals.map(v => a + v + (n.quasis[i + 1]?.value.cooked ?? ''))).slice(0, 8);
      });
      return acc;
    }
    if (n.type === 'BinaryExpression' && n.operator === '+') {
      const l = pathValues(n.left as Node, scope, depth + 1);
      const r = pathValues(n.right, scope, depth + 1);
      return l.flatMap(a => r.map(b => a + b)).slice(0, 8);
    }
    if (n.type === 'CallExpression') {
      if (n.callee.type === 'MemberExpression' && memberName(n.callee) === 'cwd'
        && n.callee.object.type === 'Identifier' && n.callee.object.name === 'process') return ['<cwd>'];
      // `[HOME, '.ssh', 'id_rsa'].join('/')`: the parts joined with a known separator
      if (n.callee.type === 'MemberExpression' && memberName(n.callee) === 'join' && n.callee.object.type === 'ArrayExpression'
        && n.arguments.length <= 1) {
        const sep = n.arguments.length === 0 ? ',' : staticString(n.arguments[0] as Node, scope);
        const parts = n.callee.object.elements;
        if (sep !== undefined && parts.length <= 16 && parts.every(e => e && e.type !== 'SpreadElement')) {
          let acc = [''];
          parts.forEach((e, i) => {
            const vals = pathValues(e as Node, scope, depth + 1);
            acc = acc.flatMap(prev => vals.map(v => (i === 0 ? v : `${prev}${sep}${v}`))).slice(0, 8);
          });
          return acc;
        }
      }
      const fn = isPathCall(n, scope, /^(?:join|resolve|normalize|dirname|fileURLToPath)$/);
      if (fn === 'fileURLToPath') return pathValues(n.arguments[0] as Node, scope, depth + 1);
      if (fn === 'dirname') {
        return pathValues(n.arguments[0] as Node, scope, depth + 1).map(v => v.includes('/') ? v.slice(0, v.lastIndexOf('/')) || '/' : '.');
      }
      if (fn) {
        let acc = [''];
        for (const a of n.arguments) {
          const vals = pathValues(a as Node, scope, depth + 1);
          acc = acc.flatMap(prev => vals.map(v => {
            if (fn === 'resolve' && (v.startsWith('/') || v.startsWith('~') || v.startsWith('<'))) return v;
            return prev ? `${prev.replace(/\/$/, '')}/${v}` : v;
          })).slice(0, 8);
        }
        return acc;
      }
    }
    // new URL('./x', import.meta.url)
    if (n.type === 'NewExpression' && n.callee.type === 'Identifier' && n.callee.name === 'URL' && n.arguments.length === 2
      && importMeta(n.arguments[1] as Node) === 'url') {
      const rel = staticString(n.arguments[0] as Node, scope);
      return rel !== undefined ? [`<skill>/${rel}`] : ['<skill>/*'];
    }
    return ['*'];
  };

  const bindingPaths = (b: Binding, depth: number): string[] => {
    const known = pathMemo.get(b);
    if (known) return known;
    pathMemo.set(b, ['*']); // cycle guard
    let vals: string[] = ['*'];
    const node = b.path.node;
    if (b.kind === 'param') {
      const values = paramArgs(b).flatMap(([arg, scope]) => pathValues(arg, scope, depth + 1));
      if (values.length > 0) vals = [...new Set(values)].slice(0, 8);
    } else if (node.type === 'VariableDeclarator' && node.id.type === 'Identifier' && b.constant) {
      vals = pathValues(node.init, b.scope, depth + 1);
    }
    pathMemo.set(b, vals);
    return vals;
  };

  /** What a parameter receives at the call sites of its function in this file. */
  const paramArgs = (b: Binding): Array<[Node, Scope]> => {
    const fnPath = b.scope.path;
    const fn = fnPath.node as { params?: Node[] };
    const index = (fn.params ?? []).findIndex(p => p === b.path.node);
    if (index < 0) return [];
    const fnBinding = functionBinding(fnPath);
    if (!fnBinding) return [];
    const out: Array<[Node, Scope]> = [];
    for (const ref of fnBinding.referencePaths.slice(0, MAX_CALL_SITES)) {
      const call = ref.parentPath;
      if (call?.isCallExpression() && call.node.callee === ref.node && call.node.arguments[index]) {
        out.push([call.node.arguments[index] as Node, call.scope]);
      }
    }
    return out;
  };

  const functionBinding = (fnPath: NodePath): Binding | undefined => {
    if (fnPath.isFunctionDeclaration() && fnPath.node.id) return fnPath.parentPath?.scope.getBinding(fnPath.node.id.name);
    const parent = fnPath.parentPath;
    if (parent?.isVariableDeclarator() && parent.node.id.type === 'Identifier') return parent.scope.getBinding(parent.node.id.name);
    return undefined;
  };

  // ---- sources ------------------------------------------------------------

  /** A file read: `fs.readFileSync(p)`, `fs.promises.readFile(p)`, imported `readFile(p)`. */
  const readCall = (n: Node, scope: Scope): Taint | undefined => {
    if (n.type !== 'CallExpression') return undefined;
    const c = n.callee;
    let fsRead = false;
    if (c.type === 'Identifier' && READ_FUNCTIONS.has(c.name)) {
      const mod = bindingModule(scope.getBinding(c.name));
      fsRead = mod ? /^(?:node:)?fs(?:\/promises)?$|^(?:fs-extra|graceful-fs)$/.test(mod) : !scope.getBinding(c.name);
    } else if (c.type === 'MemberExpression' && READ_FUNCTIONS.has(memberName(c) ?? '')) {
      const o = c.object;
      fsRead = (o.type === 'CallExpression' && o.callee.type === 'Identifier' && o.callee.name === 'require'
        && /^(?:node:)?fs(?:\/promises)?$/.test(staticString(o.arguments[0] as Node) ?? ''))
        || isFsLike(o, scope);
    }
    if (!fsRead) return undefined;
    const values = pathValues(n.arguments[0] as Node, scope, 0);
    const ranked = values.map(v => ({ v, p: classifyPath(v) }))
      .sort((a, b) => order(b.p) - order(a.p))[0] ?? { v: '*', p: 'runtime' as SourcePath };
    const resolved = normalizePath(ranked.v);
    const shown = resolved.replace(/\*/g, '…');
    return { kind: 'file', origin: `${calleeText(c)}(${shown})`, path: ranked.p, resolved: shown };
  };

  const isFsLike = (o: Node, scope: Scope): boolean => {
    if (o.type === 'MemberExpression') return memberName(o) === 'promises' && isFsLike(o.object, scope);
    if (o.type !== 'Identifier') return false;
    const mod = bindingModule(scope.getBinding(o.name));
    if (mod) return /^(?:node:)?fs(?:\/promises)?$|^(?:fs-extra|graceful-fs)$/.test(mod);
    return /^(?:fs|fsp|fsPromises|fse)$/.test(o.name);
  };

  // ---- taint of an expression -------------------------------------------

  const taintOf = (n: Node | null | undefined, scope: Scope, depth = 0): Taint[] => {
    if (!n || depth > MAX_DEPTH) return [];
    switch (n.type) {
      case 'Identifier': {
        const b = scope.getBinding(n.name);
        return b ? bindingTaint(b, depth + 1) : [];
      }
      case 'AwaitExpression':
      case 'SpreadElement':
      case 'TSAsExpression':
      case 'TSNonNullExpression':
      case 'ParenthesizedExpression':
        return taintOf((n as { argument?: Node; expression?: Node }).argument ?? (n as { expression?: Node }).expression, scope, depth + 1);
      case 'MemberExpression':
      case 'OptionalMemberExpression': {
        if (isProcessEnv(n)) return [{ kind: 'env', origin: 'process.env', wholeEnv: true }];
        if (isProcessEnv(n.object)) {
          const name = memberName(n);
          return [{ kind: 'env', origin: `process.env.${name ?? '[…]'}`, ...(name ? { envName: name } : {}) }];
        }
        if (SCALAR_METHODS.has(memberName(n) ?? '')) return [];
        return taintOf(n.object, scope, depth + 1);
      }
      case 'CallExpression':
      case 'OptionalCallExpression': {
        const read = readCall(n as Node, scope);
        if (read) return [read];
        const c = n.callee;
        if (c.type === 'MemberExpression' && HOST_CALLS.has(memberName(c) ?? '')) {
          return [{ kind: 'host', origin: `${calleeText(c)}()` }];
        }
        if (SCALAR_CALLS.test(calleeText(c as Node))) return [];
        if ((c.type === 'MemberExpression' || c.type === 'OptionalMemberExpression') && SCALAR_METHODS.has(memberName(c) ?? '')) return [];
        // A value derived from its receiver and arguments (`Buffer.from(d).toString('base64')`,
        // `JSON.stringify(x)`, `Object.entries(process.env).filter(…)`)
        const out: Taint[] = [];
        if (c.type === 'MemberExpression' || c.type === 'OptionalMemberExpression') out.push(...taintOf(c.object, scope, depth + 1));
        // The environment passes only through calls that copy or encode it:
        // `spawn(cmd, args, { env: process.env })` hands it to a child as its
        // environment, and the child's output is not the environment
        const copies = ENV_COPY_CALLS.test(calleeText(c as Node));
        for (const a of n.arguments) {
          out.push(...taintOf(a as Node, scope, depth + 1).filter(t => t.kind !== 'env' || copies));
        }
        return out;
      }
      case 'NewExpression':
        return n.arguments.flatMap(a => taintOf(a as Node, scope, depth + 1));
      case 'TemplateLiteral':
        return n.expressions.flatMap(e => taintOf(e as Node, scope, depth + 1));
      case 'TaggedTemplateExpression':
        return n.quasi.expressions.flatMap(e => taintOf(e as Node, scope, depth + 1));
      case 'BinaryExpression':
        return n.operator === '+' ? [...taintOf(n.left as Node, scope, depth + 1), ...taintOf(n.right, scope, depth + 1)] : [];
      case 'LogicalExpression':
        return [...taintOf(n.left, scope, depth + 1), ...taintOf(n.right, scope, depth + 1)];
      case 'ConditionalExpression':
        return [...taintOf(n.consequent, scope, depth + 1), ...taintOf(n.alternate, scope, depth + 1)];
      case 'SequenceExpression':
        return taintOf(n.expressions[n.expressions.length - 1], scope, depth + 1);
      case 'ArrayExpression':
        return n.elements.flatMap(e => taintOf(e as Node, scope, depth + 1));
      case 'ObjectExpression':
        return n.properties.flatMap(p => {
          if (p.type === 'SpreadElement') return taintOf(p.argument, scope, depth + 1);
          if (p.type !== 'ObjectProperty') return [];
          // Headers authenticate the request; they aren't the data it carries
          const key = p.key.type === 'Identifier' ? p.key.name : p.key.type === 'StringLiteral' ? p.key.value : '';
          if (/^headers$/i.test(key)) return [];
          return taintOf(p.value as Node, scope, depth + 1);
        });
      default:
        return [];
    }
  };

  const bindingTaint = (b: Binding, depth: number): Taint[] => {
    const known = bindingMemo.get(b);
    if (known) return known;
    bindingMemo.set(b, []); // cycle guard
    let out: Taint[] = [];
    if (b.kind === 'param') {
      out = paramTaint(b, depth);
    } else {
      const node = b.path.node;
      if (node.type === 'VariableDeclarator') {
        if (node.id.type === 'Identifier') out = taintOf(node.init, b.scope, depth + 1);
        else if (node.id.type === 'ObjectPattern' && node.init) {
          // `const { AWS_SECRET_ACCESS_KEY } = process.env`
          if (isProcessEnv(node.init)) {
            // `{ PORT = 3000 }`: a default doesn't make it the rest of the environment
            const local = (v: Node): Node => (v.type === 'AssignmentPattern' ? v.left : v);
            const prop = node.id.properties.find(p => p.type === 'ObjectProperty' && local(p.value as Node).type === 'Identifier'
              && (local(p.value as Node) as { name: string }).name === b.identifier.name);
            const key = prop?.type === 'ObjectProperty' ? (prop.key.type === 'Identifier' ? prop.key.name : prop.key.type === 'StringLiteral' ? prop.key.value : undefined) : undefined;
            out = key ? [{ kind: 'env', origin: `process.env.${key}`, envName: key }]
              : [{ kind: 'env', origin: 'process.env', wholeEnv: true }]; // `...rest`
          } else {
            out = taintOf(node.init, b.scope, depth + 1);
          }
        }
      }
      for (const v of b.constantViolations.slice(0, 8)) {
        if (v.isAssignmentExpression() && v.node.left.type === 'Identifier') out = [...out, ...taintOf(v.node.right, v.scope, depth + 1)];
      }
    }
    out = dedupe(out);
    bindingMemo.set(b, out);
    return out;
  };

  /**
   * A parameter: the value a source delivers to its callback
   * (`readFile(p).then(d => …)`, `fs.readFile(p, (err, d) => …)`,
   * `stream.on('data', chunk => …)`), else a marker for "whatever the caller
   * passes" that helper summaries are built from.
   */
  const paramTaint = (b: Binding, depth: number): Taint[] => {
    const fnPath = b.scope.path;
    const fn = fnPath.node as { params?: Node[] };
    const params = fn.params ?? [];
    const id = b.identifier;
    const index = params.findIndex(p => (p.start ?? -1) <= (id.start ?? 0) && (id.end ?? 0) <= (p.end ?? -1));
    if (index < 0) return [];
    const marker: Taint = { kind: 'param', origin: b.identifier.name, fn: fnPath.node, index };
    const call = fnPath.parentPath;
    if (!call?.isCallExpression() || !call.node.arguments.includes(fnPath.node as never)) return [marker];
    const c = call.node.callee;
    const name = memberName(c as Node);
    if ((name === 'then' || name === 'on' || name === 'once') && c.type === 'MemberExpression' && index === 0) {
      if (name !== 'then') {
        const ev = staticString(call.node.arguments[0] as Node);
        if (ev !== 'data') return [marker];
      }
      const delivered = taintOf(c.object, call.scope, depth + 1).filter(t => t.kind !== 'param');
      return delivered.length > 0 ? delivered : [marker];
    }
    // Node-style callback of the read itself: (err, data)
    const read = readCall(call.node, call.scope);
    if (read && call.node.arguments[call.node.arguments.length - 1] === fnPath.node) {
      return index === 1 ? [read] : [];
    }
    return [marker];
  };

  const dedupe = (ts: Taint[]): Taint[] => {
    const seen = new Set<string>();
    const out: Taint[] = [];
    for (const t of ts) {
      const key = `${t.kind}\0${t.origin}\0${t.index ?? ''}`;
      if (seen.has(key) || out.length >= 6) continue;
      seen.add(key);
      out.push(t);
    }
    return out;
  };

  // ---- sinks --------------------------------------------------------------

  /** What a receiver is: a network module or client, a DNS module, or fetch itself. */
  const receiverOf = (n: Node, scope: Scope, depth = 0): 'net' | 'dns' | 'fetch' | undefined => {
    if (depth > 4) return undefined;
    if (n.type === 'Identifier') {
      const b = scope.getBinding(n.name);
      if (!b) return n.name === 'fetch' ? 'fetch' : NET_NAMES.has(n.name) ? 'net' : n.name === 'dns' ? 'dns' : undefined;
      if (receiverMemo.has(b)) return receiverMemo.get(b);
      receiverMemo.set(b, undefined);
      const mod = bindingModule(b);
      let kind: 'net' | 'dns' | 'fetch' | undefined;
      if (mod) kind = DNS_MODULE.test(mod) ? 'dns' : FETCH_MODULE.test(mod) && importedFetch(b) ? 'fetch' : NET_MODULE.test(mod) ? 'net' : undefined;
      else {
        const node = b.path.node;
        if (node.type === 'VariableDeclarator' && node.init && b.constant) kind = receiverOf(node.init, b.scope, depth + 1);
      }
      receiverMemo.set(b, kind);
      return kind;
    }
    if (n.type === 'MemberExpression') {
      const name = memberName(n);
      // globalThis.fetch
      if (name === 'fetch' && n.object.type === 'Identifier' && GLOBAL_OBJECTS.has(n.object.name)) return 'fetch';
      // dns.promises
      if (name === 'promises') return receiverOf(n.object, scope, depth + 1) === 'dns' ? 'dns' : undefined;
      // `const run = axios.post` — a send method taken off a network module
      const base = receiverOf(n.object, scope, depth + 1);
      return base === 'net' && name && SEND_METHODS.has(name) ? 'fetch' : undefined;
    }
    if (n.type === 'CallExpression' || n.type === 'NewExpression') {
      const c = n.callee;
      // require('https'), axios.create(), https.request(), net.connect(), new WebSocket(url)
      if (c.type === 'Identifier' && c.name === 'require') {
        const mod = staticString(n.arguments[0] as Node, scope) ?? '';
        return DNS_MODULE.test(mod) ? 'dns' : NET_MODULE.test(mod) ? 'net' : undefined;
      }
      if (n.type === 'NewExpression' && c.type === 'Identifier' && c.name === 'WebSocket' && !scope.getBinding('WebSocket')) return 'net';
      if (c.type === 'Identifier') return receiverOf(c, scope, depth + 1) === 'net' ? 'net' : undefined;
      if (c.type === 'MemberExpression') {
        const base = receiverOf(c.object, scope, depth + 1);
        if (base === 'dns' && memberName(c) === 'Resolver') return 'dns';
        return base === 'net' ? 'net' : undefined;
      }
    }
    return undefined;
  };

  /** `import fetch from 'node-fetch'`, `const { fetch } = require('undici')`. */
  const importedFetch = (b: Binding): boolean => {
    const node = b.path.node;
    if (node.type === 'ImportDefaultSpecifier') return true;
    if (node.type === 'ImportSpecifier') return (node.imported.type === 'Identifier' ? node.imported.name : node.imported.value) === 'fetch';
    if (node.type === 'VariableDeclarator') {
      if (node.id.type === 'Identifier') return true; // const fetch = require('node-fetch')
      return node.id.type === 'ObjectPattern' && node.id.properties.some(p =>
        p.type === 'ObjectProperty' && p.key.type === 'Identifier' && p.key.name === 'fetch'
        && p.value.type === 'Identifier' && p.value.name === b.identifier.name);
    }
    return false;
  };

  interface SinkCall { name: string; object?: string; url: Node[]; body: Node[]; dns?: boolean }

  /**
   * The send a call makes, split into what goes in the address (URL, DNS
   * name) and what goes in the body. A single environment value counts only
   * in the body: an API key in a query string is how many APIs authenticate.
   */
  const sinkOf = (path: NodePath): SinkCall | undefined => {
    const n = path.node;
    if (n.type !== 'CallExpression') return undefined;
    const c = n.callee;
    const args = n.arguments as Node[];
    if (c.type === 'Identifier') {
      const kind = receiverOf(c, path.scope);
      if (kind === 'fetch') return { name: c.name === 'fetch' ? 'fetch' : `${c.name} (fetch)`, url: args.slice(0, 1), body: args.slice(1) };
      if (kind === 'dns' || (DNS_METHODS.test(c.name) && DNS_MODULE.test(bindingModule(path.scope.getBinding(c.name)) ?? ''))) {
        return { name: c.name, url: args.slice(0, 1), body: [], dns: true };
      }
      return undefined;
    }
    if (c.type !== 'MemberExpression') return undefined;
    const method = memberName(c) ?? '';
    const kind = receiverOf(c.object, path.scope);
    if (!kind && method === 'fetch' && c.object.type === 'Identifier' && GLOBAL_OBJECTS.has(c.object.name)) {
      return { name: `${c.object.name}.fetch`, url: args.slice(0, 1), body: args.slice(1) };
    }
    const object = c.object.type === 'Identifier' ? c.object.name : undefined;
    if (kind === 'dns' && DNS_METHODS.test(method)) return { name: `${object ?? 'dns'}.${method}`, object, url: args.slice(0, 1), body: [], dns: true };
    if (kind !== 'net' || !SEND_METHODS.has(method)) return undefined;
    if (method === 'send' || method === 'write' || method === 'end') return { name: method, object, url: [], body: args.slice(0, 1) };
    if (method === 'post' || method === 'put' || method === 'patch') return { name: method, object, url: args.slice(0, 1), body: args.slice(1, 2) };
    return { name: method, object, url: args.slice(0, 1), body: [] };
  };

  /** Taints of a send that count: file and whole-env anywhere, one env value in the body, host data in a DNS name. */
  const sendTaints = (sink: SinkCall, scope: Scope): Array<{ node: Node; taint: Taint }> => {
    const out: Array<{ node: Node; taint: Taint }> = [];
    for (const node of sink.url) {
      for (const t of taintOf(node, scope)) {
        if (t.kind === 'file' || t.kind === 'param' || (t.kind === 'env' && (t.wholeEnv || sink.dns)) || (t.kind === 'host' && sink.dns)) out.push({ node, taint: t });
      }
    }
    for (const node of sink.body) {
      for (const t of taintOf(node, scope)) if (t.kind !== 'host') out.push({ node, taint: t });
    }
    return out;
  };

  /** The variable a send names its data by (`secrets` in `JSON.stringify(secrets)`), else the source as written. */
  const sourceName = (node: Node, t: Taint, scope: Scope): string =>
    (t.kind === 'env' && t.envName && node.type !== 'Identifier' ? t.envName : undefined) ?? firstTainted(node, scope, 0) ?? t.origin;
  const firstTainted = (node: Node | null | undefined, scope: Scope, depth: number): string | undefined => {
    if (!node || depth > 6) return undefined;
    switch (node.type) {
      case 'Identifier': {
        const b = scope.getBinding(node.name);
        return b && bindingTaint(b, 0).length > 0 ? node.name : undefined;
      }
      case 'CallExpression':
      case 'NewExpression':
        for (const a of node.arguments) {
          const f = firstTainted(a as Node, scope, depth + 1);
          if (f) return f;
        }
        return node.callee.type === 'MemberExpression' ? firstTainted(node.callee.object, scope, depth + 1) : undefined;
      case 'MemberExpression': return firstTainted(node.object, scope, depth + 1);
      case 'AwaitExpression': return firstTainted(node.argument, scope, depth + 1);
      case 'TemplateLiteral': return node.expressions.map(e => firstTainted(e as Node, scope, depth + 1)).find(Boolean);
      case 'BinaryExpression': return firstTainted(node.left as Node, scope, depth + 1) ?? firstTainted(node.right, scope, depth + 1);
      case 'ObjectExpression':
        for (const p of node.properties) {
          const v = p.type === 'ObjectProperty' ? p.value as Node : p.type === 'SpreadElement' ? p.argument : undefined;
          const f = firstTainted(v, scope, depth + 1);
          if (f) return f;
        }
        return undefined;
      default: return undefined;
    }
  };

  // ---- walk -----------------------------------------------------------------

  interface LocalCall { path: NodePath; targets: Node[]; name: string }
  const sinkCalls: Array<{ path: NodePath; sink: SinkCall }> = [];
  const localCalls: LocalCall[] = [];
  const exportsOf = new Map<string, Node>(); // export name → function node

  const functionOf = (n: Node | null | undefined, scope: Scope): Node | undefined => {
    if (!n) return undefined;
    if (n.type === 'ArrowFunctionExpression' || n.type === 'FunctionExpression' || n.type === 'FunctionDeclaration') return n;
    if (n.type === 'Identifier') {
      const target = scope.getBinding(n.name)?.path.node;
      if (target?.type === 'FunctionDeclaration') return target;
      if (target?.type === 'VariableDeclarator') return functionOf(target.init, scope);
    }
    return undefined;
  };

  try {
    traverse(ast, {
      CallExpression(path) {
        const read = readCall(path.node, path.scope);
        if (read?.path === 'credential' && path.node.arguments[0]?.type !== 'StringLiteral') {
          credentialReads.push({ line: path.node.loc?.start.line ?? 0, resolved: read.resolved ?? '' });
        }
        const sink = sinkOf(path);
        if (sink) sinkCalls.push({ path, sink });
        const c = path.node.callee;
        if (c.type === 'Identifier') {
          const fn = functionOf(c, path.scope);
          if (fn) localCalls.push({ path, targets: [fn], name: c.name });
        }
      },
      VariableDeclarator(path) {
        const id = path.node.id;
        if (id.type !== 'Identifier' || !path.node.init) return;
        const b = path.scope.getBinding(id.name);
        const t = b ? best(bindingTaint(b, 0).filter(x => x.kind === 'file')) : undefined;
        if (t && !namedReads.has(id.name)) namedReads.set(id.name, t);
      },
      // module.exports = fn / module.exports.x = fn / exports.x = fn / module.exports = { x }
      AssignmentExpression(path) {
        const { left, right } = path.node;
        if (left.type !== 'MemberExpression') return;
        const isModuleExports = (m: Node): boolean => m.type === 'MemberExpression' && memberName(m) === 'exports'
          && m.object.type === 'Identifier' && m.object.name === 'module';
        if (isModuleExports(left)) {
          const fn = functionOf(right, path.scope);
          if (fn) exportsOf.set('default', fn);
          if (right.type === 'ObjectExpression') {
            for (const p of right.properties) {
              if (p.type !== 'ObjectProperty' || p.key.type !== 'Identifier') continue;
              const f = functionOf(p.value as Node, path.scope);
              if (f) exportsOf.set(p.key.name, f);
            }
          }
          return;
        }
        const name = memberName(left);
        if (name && (isModuleExports(left.object) || (left.object.type === 'Identifier' && left.object.name === 'exports'))) {
          const fn = functionOf(right, path.scope);
          if (fn) exportsOf.set(name, fn);
        }
      },
      ExportDefaultDeclaration(path) {
        const fn = functionOf(path.node.declaration as Node, path.scope);
        if (fn) exportsOf.set('default', fn);
      },
      ExportNamedDeclaration(path) {
        const d = path.node.declaration;
        if (d?.type === 'FunctionDeclaration' && d.id) exportsOf.set(d.id.name, d);
        if (d?.type === 'VariableDeclaration') {
          for (const v of d.declarations) {
            const fn = v.id.type === 'Identifier' ? functionOf(v.init, path.scope) : undefined;
            if (fn && v.id.type === 'Identifier') exportsOf.set(v.id.name, fn);
          }
        }
      },
    });

    // Helper summaries: which parameters of which functions reach a send.
    const summaries = new Map<Node, Map<number, { sink: string; line: number }>>();
    const addSummary = (fn: Node, index: number, sink: string, line: number): boolean => {
      const m = summaries.get(fn) ?? new Map<number, { sink: string; line: number }>();
      if (m.has(index)) return false;
      m.set(index, { sink, line });
      summaries.set(fn, m);
      return true;
    };

    for (const { path, sink } of sinkCalls) {
      const line = path.node.loc?.start.line ?? 0;
      const seen = new Set<string>();
      for (const { node, taint } of sendTaints(sink, path.scope)) {
        if (taint.kind === 'param') {
          addSummary(taint.fn!, taint.index!, sink.name, line);
          continue;
        }
        const source = sourceName(node, taint, path.scope);
        if (seen.has(`${source}\0${taint.origin}`)) continue;
        seen.add(`${source}\0${taint.origin}`);
        flows.push({ line, source, taint, sink: sink.name, ...(sink.object ? { sinkObject: sink.object } : {}), ...(sink.dns ? { dns: true } : {}) });
      }
    }

    // Helper → helper chains, to a fixpoint
    for (let round = 0; round < HELPER_ROUNDS; round++) {
      let changed = false;
      for (const call of localCalls) {
        const summary = summaries.get(call.targets[0]);
        if (!summary) continue;
        const args = (call.path.node as { arguments: Node[] }).arguments;
        for (const [index, s] of summary) {
          for (const t of taintOf(args[index], call.path.scope)) {
            if (t.kind === 'param' && addSummary(t.fn!, t.index!, `${call.name}() → ${s.sink}`, s.line)) changed = true;
          }
        }
      }
      if (!changed) break;
    }

    for (const call of localCalls) {
      const summary = summaries.get(call.targets[0]);
      if (!summary) continue;
      const args = (call.path.node as { arguments: Node[] }).arguments;
      const line = call.path.node.loc?.start.line ?? 0;
      for (const [index, s] of summary) {
        const taint = best(taintOf(args[index], call.path.scope).filter(t => t.kind !== 'param' && t.kind !== 'host'));
        if (taint && args[index]) flows.push({ line, source: sourceName(args[index], taint, call.path.scope), taint, sink: s.sink, via: call.name });
      }
    }

    // Calls into the skill's own modules: `require('./lib/upload')(d)`, `import { send } from './net.js'`
    for (const { path } of [...localCallsOfModules(ast)]) {
      const n = path.node as { callee: Node; arguments: Node[] };
      const target = localModuleTarget(path);
      if (!target) continue;
      n.arguments.forEach((arg, argIndex) => {
        const taint = best(taintOf(arg, path.scope).filter(t => t.kind !== 'param' && t.kind !== 'host'));
        if (taint) moduleCalls.push({ line: path.node.loc?.start.line ?? 0, module: target.module, exportName: target.exportName, argIndex, source: sourceName(arg, taint, path.scope), taint });
      });
    }

    for (const [exportName, fn] of exportsOf) {
      for (const [paramIndex, s] of summaries.get(fn) ?? []) paramSinks.push({ exportName, paramIndex, sink: s.sink, line: s.line });
    }
  } catch {
    // Pathological ASTs — keep what was found
  }

  return { flows, moduleCalls, paramSinks, credentialReads, namedReads };
}

const RELATIVE = /^\.\.?\//;

/** Every call whose callee may come from a relative module (collected lazily, one walk). */
function localCallsOfModules(ast: JsAst): Array<{ path: NodePath }> {
  const out: Array<{ path: NodePath }> = [];
  traverse(ast, {
    CallExpression(path) {
      const c = path.node.callee;
      if (c.type === 'Identifier' || c.type === 'MemberExpression' || c.type === 'CallExpression') out.push({ path });
    },
  });
  return out;
}

/** The relative module and export a call reaches: `upload(d)` with `const upload = require('./lib/upload')`. */
function localModuleTarget(path: NodePath): { module: string; exportName: string } | undefined {
  const c = (path.node as { callee: Node }).callee;
  const requireOf = (n: Node | null | undefined): string | undefined =>
    n?.type === 'CallExpression' && n.callee.type === 'Identifier' && n.callee.name === 'require'
      ? staticString(n.arguments[0] as Node) : undefined;
  // require('./x')(d) / require('./x').send(d)
  const direct = requireOf(c);
  if (direct && RELATIVE.test(direct)) return { module: direct, exportName: 'default' };
  if (c.type === 'MemberExpression') {
    const viaRequire = requireOf(c.object);
    const name = memberName(c);
    if (viaRequire && RELATIVE.test(viaRequire) && name) return { module: viaRequire, exportName: name };
    if (c.object.type === 'Identifier' && name) {
      const b = path.scope.getBinding(c.object.name);
      const mod = bindingModule(b);
      if (mod && RELATIVE.test(mod) && b && (b.path.node.type === 'ImportNamespaceSpecifier' || b.path.node.type === 'VariableDeclarator')) {
        return { module: mod, exportName: name };
      }
    }
    return undefined;
  }
  if (c.type !== 'Identifier') return undefined;
  const b = path.scope.getBinding(c.name);
  const mod = bindingModule(b);
  if (!b || !mod || !RELATIVE.test(mod)) return undefined;
  const node = b.path.node;
  if (node.type === 'ImportDefaultSpecifier') return { module: mod, exportName: 'default' };
  if (node.type === 'ImportSpecifier') return { module: mod, exportName: node.imported.type === 'Identifier' ? node.imported.name : node.imported.value };
  if (node.type === 'VariableDeclarator') {
    if (node.id.type === 'Identifier') return { module: mod, exportName: 'default' };
    if (node.id.type === 'ObjectPattern') {
      for (const p of node.id.properties) {
        if (p.type === 'ObjectProperty' && p.value.type === 'Identifier' && p.value.name === c.name && p.key.type === 'Identifier') {
          return { module: mod, exportName: p.key.name };
        }
      }
    }
  }
  return undefined;
}

function order(p: SourcePath): number {
  return { credential: 4, outside: 3, workspace: 1, own: 0, runtime: 2 }[p];
}
