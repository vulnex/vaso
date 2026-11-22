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
import { posix } from 'node:path';
import { parseJs, significantLength, sourceChunks, type JsAst, type SourceChunk } from './js-parse.js';

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
  /** In a module the tracer did not follow into from a tool handler (size cap): fed by what its exports receive, tool input or not (findUnverifiedSinks). */
  unverified?: boolean;
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
/** Helpers summarized inside one another (a return chain `a(b(c(…)))` through that many functions). */
const MAX_SUMMARY_NESTING = 64;
/** Caller-parameter → callee-parameter links recorded for one group. */
const MAX_FLOW_EDGES = 200_000;
/** Parameters one value is tracked as depending on. */
const MAX_DEPS = 16;
const MAX_CACHED = 1_000;

/** A parameter (by position) of a function: a value that came from it carries whatever its callers pass. */
interface ParamDep {
  fn: Node;
  index: number;
  /** How the value was derived from it, e.g. `line ← cmd`. */
  chain: string;
}

/** What a value carries: tool input (`origin`, how it was reached), or what the listed parameters receive. */
interface Taint {
  origin?: string;
  deps: ParamDep[];
}

const CLEAN: Taint = { deps: [] };

function isClean(t: Taint): boolean {
  return !t.origin && t.deps.length === 0;
}

/** Both values' input: the first certain origin, and their parameters (deduplicated, bounded). */
function mergeTaint(a: Taint, b: Taint): Taint {
  if (isClean(b)) return a;
  if (isClean(a)) return b;
  const deps = [...a.deps];
  for (const d of b.deps) {
    if (deps.length >= MAX_DEPS) break;
    if (!deps.some((x) => x.fn === d.fn && x.index === d.index)) deps.push(d);
  }
  return { ...(a.origin || b.origin ? { origin: a.origin ?? b.origin } : {}), deps };
}

/** A value held under `name`: `name ← …` in front of how it was derived. */
function renamed(name: string, t: Taint): Taint {
  if (isClean(t)) return CLEAN;
  return {
    ...(t.origin ? { origin: t.origin === name ? name : `${name} ← ${t.origin}` } : {}),
    deps: t.deps.map((d) => (d.chain === name ? d : { ...d, chain: `${name} ← ${d.chain}` })),
  };
}

/** The argument a call passes at a parameter position; a spread before it may hold it. */
function argumentAt(args: NodePath[], index: number): NodePath | undefined {
  for (let i = 0; i < args.length && i <= index; i++) {
    if (args[i].isSpreadElement()) return args[i].get('argument') as NodePath;
  }
  return args[index];
}
const cache = new Map<string, TaintedSink[]>();
/**
 * Most source analyzed as one program: files that import each other are
 * parsed and traced together, so all their ASTs are alive at once (2 MB of
 * linked modules held ~600 MB). Measured without comments and whitespace
 * (significantLength). Links that would grow a group past this are not
 * followed (see taintCoverage); each side is still traced with its other links.
 */
export const MAX_GROUP_SOURCE = 512 * 1024;
/**
 * A module already in one handler group that another handler group imports
 * (a shared helper) is traced in both up to this size; the copies together up
 * to MAX_SHARED_TOTAL. Past either, the link is recorded as not followed.
 */
export const MAX_SHARED_MODULE = 64 * 1024;
const MAX_SHARED_TOTAL = 2 * MAX_GROUP_SOURCE;

export function findTaintedSinks(code: string, filename = 'unknown.js'): TaintedSink[] {
  return traced(code, filename).filter((s) => !s.unverified).map((s) => ({ ...s }));
}

/**
 * Sinks in modules a tool handler's file imports that its traced group left
 * out (the size cap) and that take a parameter of a function those modules
 * export: whether tool input reaches them is not known — "not verified", never
 * clean. Each has `unverified: true`.
 */
export function findUnverifiedSinks(code: string, filename = 'unknown.js'): TaintedSink[] {
  return traced(code, filename).filter((s) => s.unverified).map((s) => ({ ...s }));
}

function traced(code: string, filename: string): TaintedSink[] {
  const key = `${filename}\0${createHash('sha1').update(code).digest('base64')}`;
  const cached = cache.get(key);
  if (cached) return cached;
  const chunks = sourceChunks(code);
  const plan = planModules(chunks);
  const untraced = new Set(plan.untraced.map((m) => chunks[m.index].path!));
  // A module shared by overlapping groups is reported once per sink: the first
  // report, unless a later group traces tool input where it was only unverified
  const sinkKey = (s: TaintedSink): string => `${s.line}\0${s.kind}\0${s.sink}`;
  const verified = new Map<string, boolean>();
  let results: TaintedSink[] = [];
  for (const group of plan.groups) {
    const found = analyze(group.map((i) => chunks[i]), untraced);
    const fresh = found.filter((s) => {
      const had = verified.get(sinkKey(s));
      return had === undefined || (!had && !s.unverified);
    });
    for (const s of fresh) {
      if (!s.unverified && verified.get(sinkKey(s)) === false) results = results.filter((r) => sinkKey(r) !== sinkKey(s) || !r.unverified);
    }
    for (const s of fresh) verified.set(sinkKey(s), verified.get(sinkKey(s)) === true || !s.unverified);
    results.push(...fresh);
  }
  results.sort((a, b) => a.line - b.line);
  if (cache.size >= MAX_CACHED) cache.delete(cache.keys().next().value!);
  cache.set(key, results);
  return results;
}

/** A module of a joined source the tracer did not follow into from a tool handler's file (the group size cap). */
export interface UntracedModule {
  /** Its path, as its `// === path ===` header names it. */
  path: string;
  /** The module(s) whose import of it was not followed, comma-separated. */
  from: string;
  /** Its lines in the joined source (first, last). */
  startLine: number;
  endLine: number;
}

/**
 * How far cross-module tracing got in a joined multi-file source: the
 * modules a tool handler's file imports (directly or not) that were left out
 * of its traced group for the size cap. Tool input reaching them is not
 * traced, so a sink there is unknown, not clean. Text-only; no parse.
 */
export function taintCoverage(code: string): { untraced: UntracedModule[] } {
  const key = createHash('sha1').update(code).digest('base64');
  let untraced = coverageCache.get(key);
  if (!untraced) {
    const chunks = sourceChunks(code);
    untraced = planModules(chunks).untraced.map(({ index, from }) => ({
      path: chunks[index].path!,
      from: from.map((f) => chunks[f].path!).join(', '),
      startLine: chunks[index].startLine,
      endLine: chunks[index].startLine + chunks[index].code.split('\n').length - 1,
    }));
    if (coverageCache.size >= MAX_CACHED) coverageCache.delete(coverageCache.keys().next().value!);
    coverageCache.set(key, untraced);
  }
  return { untraced: untraced.map((m) => ({ ...m })) };
}
const coverageCache = new Map<string, UntracedModule[]>();

/** A relative module specifier in `import … from`, `export … from`, `import(…)`, `require(…)`. */
const RELATIVE_SPECIFIER = /(?:\bfrom|\bimport|\brequire)\s*(?:\(\s*)?(["'`])(\.{1,2}\/[^"'`\r\n]{0,512})\1/g;
const JS_EXTENSIONS = ['.js', '.mjs', '.cjs', '.ts', '.mts', '.cts', '.jsx', '.tsx'];

/**
 * The chunk a relative specifier names, from the chunk at `from`: as written,
 * with an extension, or a directory's index; `./x.js` may be `./x.ts` in
 * TypeScript source (the candidates the source resolver tries on disk).
 */
function resolveChunk<T>(from: string, specifier: string, byPath: Map<string, T>): T | undefined {
  const base = posix.normalize(posix.join(posix.dirname(from), specifier.replace(/[?#].*$/, '')));
  const ext = posix.extname(base).toLowerCase();
  const candidates = JS_EXTENSIONS.includes(ext)
    ? [base, base.replace(/\.([mc]?)js$/i, '.$1ts'), base.replace(/\.js$/i, '.tsx')]
    : [...JS_EXTENSIONS.map((e) => base + e), ...JS_EXTENSIONS.map((e) => `${base}/index${e}`)];
  for (const c of candidates) {
    const at = byPath.get(c);
    if (at !== undefined) return at;
  }
  return undefined;
}

/** A file that registers a tool/request handler (HANDLER_REGISTRARS): where tool input enters. */
const HANDLER_REGISTRATION = /\.\s*(?:tool|registerTool|setRequestHandler|addTool)\s*\(|\[\s*(["'`])(?:tool|registerTool|setRequestHandler|addTool)\1\s*\]\s*\(/;

interface ModulePlan {
  /** Chunks (by index) to trace together. */
  groups: number[][];
  /** Modules a handler file reaches by imports that its group left out for size, with the importers whose link was dropped. */
  untraced: Array<{ index: number; from: number[] }>;
}

/**
 * Text that suggests a sink the tracer reports — process or code execution,
 * the filesystem, SQL, the network. Only orders which modules join a handler's
 * group first; it decides no finding. Tested on hintText (comments and string
 * contents blanked): a `// exec(` comment or an `"exec("` string must not
 * promote a module.
 */
const SINK_HINT =/\bchild_|\b(?:exec|execSync|execFile|execFileSync|spawn|spawnSync|fork|eval|Function|fetch|promisify)\s*\(|\bvm\b|\bfs\b|fs\/promises|fs-extra|\b(?:readFile|writeFile|appendFile|unlink|rm|rmdir|mkdir|createReadStream|createWriteStream|readdir|copyFile|rename|open)(?:Sync)?\s*\(|\.(?:query|execute|raw|prepare|exec|run)\s*\(|\brequire\s*\(\s*[^'"`\s)]|\bimport\s*\(/;

/** A string literal hintText keeps: a module that names a sink (`from 'node:child_process'`). */
const SINK_MODULE_NAME = /^(?:node:)?(?:child_process|fs(?:\/promises)?|vm)$|^(?:fs-extra|graceful-fs)$/;

/**
 * `code` with comments removed and string contents blanked (a string that is
 * a sink module's name is kept), for SINK_HINT. Template interpolations stay
 * code. One pass; regex literals are not recognized — this only orders a
 * group, so a misread costs ordering, not a finding.
 */
export function hintText(code: string): string {
  let out = '';
  let from = 0;
  // open template literals, by the brace depth their `${` opened at
  const templates: number[] = [];
  let depth = 0;
  const cut = (start: number, end: number, keep: boolean): void => {
    out += code.slice(from, keep ? end : start);
    from = end;
  };
  /** Blanks template text from `start` to the closing backtick or the next `${`; the index to resume after. */
  const templateTail = (start: number): number => {
    let j = start;
    while (j < code.length && code[j] !== '`' && !(code[j] === '$' && code[j + 1] === '{')) j += code[j] === '\\' ? 2 : 1;
    cut(start, Math.min(j, code.length), false);
    if (code[j] === '$') {
      templates.push(depth);
      return j + 1; // the `{`: skipped, so the depth stays the template's
    }
    return j;
  };
  for (let i = 0; i < code.length; i++) {
    const c = code[i];
    if (c === '/' && code[i + 1] === '/') {
      const end = code.indexOf('\n', i);
      if (end === -1) { cut(i, code.length, false); break; }
      cut(i, end, false);
      i = end;
    } else if (c === '/' && code[i + 1] === '*') {
      const end = code.indexOf('*/', i + 2);
      if (end === -1) { cut(i, code.length, false); break; }
      cut(i, end + 2, false);
      out += ' ';
      i = end + 1;
    } else if (c === '{') {
      depth++;
    } else if (c === '}') {
      if (templates.length && templates[templates.length - 1] === depth) {
        templates.pop();
        i = templateTail(i + 1);
      } else depth--;
    } else if (c === "'" || c === '"') {
      let j = i + 1;
      while (j < code.length && code[j] !== c && code[j] !== '\n') j += code[j] === '\\' ? 2 : 1;
      j = Math.min(j, code.length);
      cut(i + 1, j, SINK_MODULE_NAME.test(code.slice(i + 1, j)));
      i = j;
    } else if (c === '`') {
      i = templateTail(i + 1);
    }
  }
  return out + code.slice(from);
}

/**
 * What a module costs a group's budget. Its significant length — except a
 * data module (literals only: no call, function, class, `new`, regex or
 * template interpolation), whose AST is a list of literal nodes: a string
 * there costs a few bytes whatever its length. Padding a handler's imports
 * with big string tables then doesn't push the code out of the group.
 * Numbers and keys outside strings count in full (their nodes are dense).
 */
export function moduleWeight(code: string): number {
  const full = significantLength(code);
  const CODE_WORDS = /^(?:function|class|new|get|set|async|await|yield|with|this|super)$/;
  let outside = 0;
  let strings = 0;
  let quote = '';
  let comment: '' | 'line' | 'block' = '';
  let word = '';
  let last = '';
  for (let i = 0; i < code.length; i++) {
    const c = code[i];
    if (comment === 'line') {
      if (c === '\n') comment = '';
      continue;
    }
    if (comment === 'block') {
      if (c === '*' && code[i + 1] === '/') { comment = ''; i++; }
      continue;
    }
    if (quote) {
      if (c === '\\') i++;
      else if (quote === '`' && c === '$' && code[i + 1] === '{') return full;
      else if (c === quote || (c === '\n' && quote !== '`')) quote = '';
      continue;
    }
    if (/[\w$]/.test(c)) {
      word += c;
      outside++;
      continue;
    }
    if (word) {
      // (`import x from './d.js'` is a declaration; `import(…)` is caught by its paren)
      if (CODE_WORDS.test(word)) return full;
      last = word;
      word = '';
    }
    if (c === '/') {
      if (code[i + 1] === '/') { comment = 'line'; i++; continue; }
      if (code[i + 1] === '*') { comment = 'block'; i++; continue; }
      return full; // a regex or a division: not a data module
    }
    if (c === ' ' || c === '\t' || c === '\n' || c === '\r') continue;
    // a call, a function, a getter (`(`), an arrow (`=>`); a tagged template
    // calls its tag (`run`cmd``, `a[0]`x``)
    if (c === '(' || (c === '=' && code[i + 1] === '>')) return full;
    if (c === '`' && (last || /[\])]/.test(code[i - 1] ?? ''))) return full;
    last = '';
    if (c === "'" || c === '"' || c === '`') { quote = c; strings++; continue; }
    outside++;
  }
  if (CODE_WORDS.test(word)) return full;
  return Math.min(full, Math.max(outside + 8 * strings, code.length >> 6));
}

/**
 * Chunks (by index) to trace together, in groups of at most MAX_GROUP_SOURCE.
 * Tool input enters in the files that register handlers, so their group is
 * grown first, outward along their imports (breadth first: the modules they
 * import before the ones those import) — first through the modules that hold
 * or lead to a sink (SINK_HINT), then the rest, so sink-free modules can't
 * crowd the code tool input reaches out of the group; data modules count at
 * their literal cost (moduleWeight). A module that doesn't fit is skipped
 * and recorded, the rest still join. A module an earlier handler group holds
 * joins this one too when small (MAX_SHARED_MODULE, MAX_SHARED_TOTAL in all),
 * else its link is recorded; groups may overlap, and traced() keeps one
 * report per sink. The other files are grouped by their
 * links as before (a link that would join two groups past the cap is
 * dropped). One scan of each file's text for specifiers — linear in the source.
 */
function planModules(chunks: SourceChunk[]): ModulePlan {
  const n = chunks.length;
  const byPath = new Map<string, number>();
  chunks.forEach((c, i) => { if (c.path && !byPath.has(c.path)) byPath.set(c.path, i); });
  const links: number[][] = chunks.map(() => []);
  if (byPath.size > 1) {
    chunks.forEach((c, i) => {
      if (!c.path) return;
      for (const m of c.code.matchAll(RELATIVE_SPECIFIER)) {
        const j = resolveChunk(c.path, m[2], byPath);
        if (j !== undefined && j !== i && !links[i].includes(j)) links[i].push(j);
      }
    });
  }
  if (n === 1 || byPath.size <= 1) return { groups: chunks.map((_, i) => [i]), untraced: [] };
  const size = chunks.map((c) => moduleWeight(c.code));
  // Modules that hold a sink or import (directly or not) one that does
  const toSink = chunks.map((c) => SINK_HINT.test(hintText(c.code)));
  const importers: number[][] = chunks.map(() => []);
  links.forEach((targets, i) => { for (const t of targets) importers[t].push(i); });
  const back = toSink.flatMap((s, i) => (s ? [i] : []));
  for (let q = 0; q < back.length; q++) {
    for (const i of importers[back[q]]) if (!toSink[i]) { toSink[i] = true; back.push(i); }
  }
  const isHandler = chunks.map((c) => !!c.path && HANDLER_REGISTRATION.test(c.code));
  // the group a module was first placed in; `members` also holds shared copies
  const groupOf = new Array<number>(n).fill(-1);
  const groups: number[][] = [];
  const members: Set<number>[] = [];
  const total: number[] = [];
  // links left out for size: the module, the importer and the importer's group
  const dropped = new Map<number, Array<{ from: number; g: number }>>();
  const drop = (t: number, from: number, g: number): void => {
    const list = dropped.get(t) ?? [];
    if (list.length === 0) dropped.set(t, list);
    if (!list.some((d) => d.from === from)) list.push({ from, g });
  };
  // links into a module another group holds that could not be shared
  const crossed = new Map<number, number[]>();
  const cross = (t: number, from: number): void => {
    const list = crossed.get(t) ?? [];
    if (list.length === 0) crossed.set(t, list);
    if (!list.includes(from)) list.push(from);
  };
  let shared = 0;
  const add = (i: number, g: number): void => {
    members[g].add(i);
    groups[g].push(i);
    total[g] += size[i];
  };
  const join = (i: number, g: number): void => {
    groupOf[i] = g;
    add(i, g);
  };

  // Handler files and what they import, breadth first
  let current = -1;
  const handlerFiles: number[] = [];
  for (let h = 0; h < n; h++) {
    if (!isHandler[h]) continue;
    handlerFiles.push(h);
    if (groupOf[h] !== -1) continue;
    if (current === -1 || total[current] + size[h] > MAX_GROUP_SOURCE) {
      current = groups.length;
      groups.push([]);
      members.push(new Set());
      total.push(0);
    }
    join(h, current);
    // Along the links to sinks first, then every link from what joined
    const queue = [h];
    for (const sinkward of [true, false]) {
      for (let q = 0; q < queue.length; q++) {
        for (const t of links[queue[q]]) {
          if (members[current].has(t) || (sinkward && !toSink[t])) continue;
          const fits = total[current] + size[t] <= MAX_GROUP_SOURCE;
          if (groupOf[t] === -1) {
            if (!fits) {
              drop(t, queue[q], current);
              continue;
            }
            join(t, current);
          } else {
            // Held by another group. A handler file is traced there from its
            // own handlers. A helper the handlers here call (a shared `run()`,
            // a re-export) is traced here too while small — groups overlap,
            // within a budget; past it, the link is recorded as not followed.
            if (isHandler[t]) continue;
            if (!fits || size[t] > MAX_SHARED_MODULE || shared + size[t] > MAX_SHARED_TOTAL) {
              cross(t, queue[q]);
              continue;
            }
            shared += size[t];
            add(t, current);
          }
          queue.push(t);
        }
      }
    }
  }
  // Modules a handler file reaches only through a dropped link: not traced from it
  const untraced: Array<{ index: number; from: number[] }> = [];
  const seen = new Set<number>(handlerFiles);
  const queue = [...handlerFiles];
  for (let q = 0; q < queue.length; q++) {
    for (const t of links[queue[q]]) {
      if (seen.has(t)) continue;
      seen.add(t);
      queue.push(t);
      if (groupOf[t] === -1) untraced.push({ index: t, from: dropped.get(t)?.map((d) => d.from) ?? [queue[q]] });
    }
  }
  // the shared helpers some group could not take in, and a module left out of
  // one group for size that a later group took in: the first group's
  // handlers still lost it
  const lost = new Map(crossed);
  for (const [t, list] of dropped) {
    if (groupOf[t] === -1 || isHandler[t]) continue;
    for (const d of list) if (!members[d.g].has(t)) lost.set(t, [...(lost.get(t) ?? []), d.from].filter((f, i, a) => a.indexOf(f) === i));
  }
  const listed = new Set(untraced.map((u) => u.index));
  for (const [index, from] of lost) if (!listed.has(index)) untraced.push({ index, from });

  // The rest: linked files together, as far as the cap allows
  const parent = chunks.map((_, i) => i);
  const weight = [...size];
  const find = (i: number): number => {
    while (parent[i] !== i) i = parent[i] = parent[parent[i]];
    return i;
  };
  for (let i = 0; i < n; i++) {
    if (groupOf[i] !== -1) continue;
    for (const j of links[i]) {
      if (groupOf[j] !== -1) continue;
      const a = find(i);
      const b = find(j);
      if (a === b || weight[a] + weight[b] > MAX_GROUP_SOURCE) continue;
      parent[b] = a;
      weight[a] += weight[b];
    }
  }
  const byRoot = new Map<number, number>();
  for (let i = 0; i < n; i++) {
    if (groupOf[i] !== -1) continue;
    const root = find(i);
    let g = byRoot.get(root);
    if (g === undefined) {
      byRoot.set(root, (g = groups.length));
      groups.push([]);
      members.push(new Set());
      total.push(0);
    }
    join(i, g);
  }
  return { groups, untraced: untraced.sort((a, b) => a.index - b.index) };
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

/** TypeScript's (and tslib's) CommonJS interop wrappers around a `require`: `__importStar(require('m'))`. */
const INTEROP_HELPERS = /^__import(?:Star|Default)$/;

/** The name a callee calls: `f`, `o.f`, `(0, o.f)`. */
function calleeName(callee: Node): string | undefined {
  const c = callee.type === 'SequenceExpression' ? callee.expressions[callee.expressions.length - 1] : callee;
  return c.type === 'Identifier' ? c.name : memberName(c);
}

/**
 * `require('m')` / `await import('m')` / `import('m')` → `m` (the name may be
 * built from constants), also through TypeScript's interop wrappers
 * (`__importStar(require('m'))`, `tslib_1.__importDefault(require('m'))`).
 */
function moduleOfInit(init: Node | null | undefined, scope?: Scope, depth = 0): string | undefined {
  if (!init || depth > 4) return undefined;
  if (init.type === 'AwaitExpression') return moduleOfInit(init.argument, scope, depth + 1);
  if (init.type === 'CallExpression') {
    const { callee, arguments: args } = init;
    if (isRequireCallee(callee) || callee.type === 'Import') return staticString(args[0] as Node, scope);
    if (args.length === 1 && INTEROP_HELPERS.test(calleeName(callee as Node) ?? '')) return moduleOfInit(args[0] as Node, scope, depth + 1);
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
  if (binding.kind === 'param') return thenModule(binding);
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
 * The module a callback's first parameter receives from a dynamic import:
 * `m` in `import('child_process').then(m => m.execSync(x))`.
 */
function thenModule(binding: Binding): string | undefined {
  const fn = binding.scope.path;
  const call = fn.parentPath;
  if (!fn.isFunction() || !call?.isCallExpression() || call.node.arguments[0] !== fn.node) return undefined;
  const first = fn.node.params[0];
  if (first?.type !== 'Identifier' || first.name !== binding.identifier.name) return undefined;
  const callee = call.node.callee;
  if (callee.type !== 'MemberExpression' || memberName(callee) !== 'then') return undefined;
  const object = callee.object;
  return object.type === 'ImportExpression' || (object.type === 'CallExpression' && object.callee.type === 'Import')
    ? moduleOfInit(object, call.scope) : undefined;
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
    // `const e = eval; e(code)`: the global eval or Function under another name
    if (binding?.constant && decl?.type === 'VariableDeclarator' && decl.init?.type === 'Identifier'
      && CODE_SINKS.has(decl.init.name) && !binding.path.scope.getBinding(decl.init.name)) {
      return { display: `${name} (${decl.init.name})`, kind: 'code', fn: decl.init.name };
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
  // (a computed name may be assembled from constants: `globalThis['ev' + 'al']`)
  const prop = memberName(callee) ?? (callee.computed ? staticString(callee.property as Node, path.scope) : undefined);
  if (prop === undefined) return undefined;
  const object = callee.object;
  // `Reflect.apply(eval, null, [code])`, `eval.call(null, code)`: eval or
  // Function invoked through the function-call helpers
  const args = (path.node as { arguments?: Node[] }).arguments ?? [];
  const unboundCodeSink = (n: Node | undefined): n is Node & { type: 'Identifier'; name: string } =>
    n?.type === 'Identifier' && CODE_SINKS.has(n.name) && !path.scope.getBinding(n.name);
  if ((prop === 'apply' || prop === 'construct') && object.type === 'Identifier' && object.name === 'Reflect'
    && !path.scope.getBinding('Reflect') && unboundCodeSink(args[0])) {
    return { display: `Reflect.${prop}(${args[0].name})`, kind: 'code', fn: args[0].name };
  }
  if ((prop === 'call' || prop === 'apply' || prop === 'bind') && unboundCodeSink(object)) {
    return { display: `${object.name}.${prop}`, kind: 'code', fn: object.name };
  }
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

/** A file of a traced group, parsed. */
interface ModuleFile {
  chunk: SourceChunk;
  ast: JsAst;
  /** Functions it exports by name (`default`; `default.f` for a member of an exported object), filled on first use. */
  exports?: Map<string, ExportEntry>;
  /** Modules whose exports it re-exports whole (`export * from`, `module.exports = require(…)`). */
  stars?: ModuleFile[];
  lines?: string[];
}
/** A function it exports, a name it forwards from another module, or an instance of one of its classes (`export const tm = new TerminalManager()`). */
type ExportEntry = { fn: NodePath } | { from: ModuleFile; name: string } | { cls: NodePath };

/** Array methods whose callback receives the receiver's elements as its first parameter (`reduce`: its second). */
const ELEMENT_CALLBACKS: Record<string, number> = {
  forEach: 0, map: 0, flatMap: 0, filter: 0, some: 0, every: 0, find: 0, findIndex: 0, findLast: 0, findLastIndex: 0, reduce: 1, reduceRight: 1,
};
/** Functions of an object a computed call (`handlers[name](args)`) may reach, at most. */
const MAX_DISPATCH_TARGETS = 256;

/** The class a `new X(…)` expression instantiates, when `X` is a class of this file. */
function classOfNew(p: NodePath | null | undefined): NodePath | undefined {
  if (!p?.isNewExpression()) return undefined;
  const callee = p.get('callee') as NodePath;
  if (callee.isClassExpression()) return callee;
  if (!callee.isIdentifier()) return undefined;
  const b = callee.scope.getBinding(callee.node.name);
  if (b?.path.isClassDeclaration()) return b.path;
  if (b?.path.isVariableDeclarator()) {
    const init = b.path.get('init') as NodePath;
    if (init.isClassExpression()) return init;
  }
  return undefined;
}

/** The method `name` of a class (or of a class of this file it extends, a few levels up). */
function classMethod(cls: NodePath, name: string, depth = 0): NodePath | undefined {
  const body = cls.get('body') as NodePath;
  for (const m of (body.get('body') as NodePath[])) {
    if ((m.isClassMethod() || m.isClassPrivateMethod()) && m.node.kind === 'method' && keyName(m.node.key, m.node.computed) === name) return m;
    // `run = (cmd) => …` as a class field
    if (m.isClassProperty() && keyName(m.node.key, m.node.computed) === name) {
      const value = m.get('value') as NodePath;
      if (value.isArrowFunctionExpression() || value.isFunctionExpression()) return value;
    }
  }
  const sup = cls.get('superClass') as NodePath;
  if (depth >= 4 || !sup.isIdentifier()) return undefined;
  const b = sup.scope.getBinding(sup.node.name);
  const parent = b?.path.isClassDeclaration() ? b.path : undefined;
  return parent ? classMethod(parent, name, depth + 1) : undefined;
}

/** `module.exports` */
function isModuleExports(node: Node): boolean {
  return node.type === 'MemberExpression' && node.object.type === 'Identifier' && node.object.name === 'module' && memberName(node) === 'exports';
}

/** A key of an object literal or an export specifier, when written as a name or a string. */
function keyName(node: Node, computed = false): string | undefined {
  if (node.type === 'Identifier' && !computed) return node.name;
  return node.type === 'StringLiteral' ? node.value : undefined;
}

/**
 * Traces a group of files that import each other as one program: tool input
 * reaching a function another module exports (`import { run } from
 * './helpers.js'`, `const h = require('./h')`, re-exports) follows it there.
 */
function analyze(chunks: SourceChunk[], untraced: ReadonlySet<string> = new Set()): TaintedSink[] {
  const files: ModuleFile[] = [];
  for (const chunk of chunks) {
    const ast = parseJs(chunk.code);
    if (ast) files.push({ chunk, ast });
  }
  if (files.length === 0) return [];
  const byPath = new Map<string, ModuleFile>();
  const fileOfProgram = new WeakMap<Node, ModuleFile>();
  for (const file of files) {
    if (file.chunk.path && !byPath.has(file.chunk.path)) byPath.set(file.chunk.path, file);
    fileOfProgram.set(file.ast.program, file);
  }
  const linked = byPath.size > 1;

  let current = files[0];
  const lineText = (line: number): string => (current.lines ??= current.chunk.code.split('\n'))[line - 1]?.trim() ?? '';
  const results: TaintedSink[] = [];
  /** A finding at `line` of the file being walked, placed in the joined source. */
  const pushResult = (line: number, sink: Omit<TaintedSink, 'line' | 'snippet' | 'sourceLine'>): void => {
    results.push({ line: line + current.chunk.startLine - 1, ...cutLine(lineText(line)), ...sink });
  };
  // A throw in one file's walk (a pathological AST) loses that walk, not the group's
  const safely = (walk: () => void): void => {
    try { walk(); } catch { /* report what was found so far */ }
  };

  /** The file of the group a relative specifier names, seen from `path`'s file. */
  const moduleAt = (path: NodePath, specifier: string | undefined): ModuleFile | undefined => {
    if (!linked || !specifier?.startsWith('.')) return undefined;
    const from = fileOfProgram.get(path.scope.getProgramParent().block)?.chunk.path;
    return from ? resolveChunk(from, specifier, byPath) : undefined;
  };

  /** The function `p` is or names in its own file: inline, a function declaration, or a function-valued constant. */
  const functionAt = (p: NodePath | null | undefined): NodePath | undefined => {
    if (!p?.node) return undefined;
    if (p.isFunctionDeclaration() || p.isFunctionExpression() || p.isArrowFunctionExpression() || p.isObjectMethod()) return p;
    if (!p.isIdentifier()) return undefined;
    const b = p.scope.getBinding(p.node.name);
    if (b?.path.isFunctionDeclaration()) return b.path;
    if (b?.path.isVariableDeclarator()) {
      const init = b.path.get('init');
      if (init.isFunctionExpression() || init.isArrowFunctionExpression()) return init;
    }
    return undefined;
  };

  /** The module of the group a CommonJS binding holds: `const h = require('./h')`, `const h_1 = __importStar(require("./h"))`. */
  const requiredModule = (object: NodePath): ModuleFile | undefined => {
    if (!object.isIdentifier()) return moduleAt(object, moduleOfInit(object.node, object.scope));
    const b = object.scope.getBinding(object.node.name);
    const decl = b?.path.node;
    return decl?.type === 'VariableDeclarator' && decl.id.type === 'Identifier' ? moduleAt(b!.path, moduleOfInit(decl.init, b!.scope)) : undefined;
  };

  /**
   * What an exported value stands for: a function of the file, or a name
   * another module of the group exports — an imported binding passed on
   * (`import { run } from './h'; export { run }`, `const { run } =
   * require('./h')`), or a member of a required module (`exports.run =
   * h_1.run`).
   */
  const exportEntry = (p: NodePath | null | undefined): ExportEntry | undefined => {
    if (!p?.node) return undefined;
    const fn = functionAt(p);
    if (fn) return { fn };
    const cls = instanceClass(p);
    if (cls) return { cls };
    if (p.isMemberExpression()) {
      const name = memberName(p.node);
      const from = name === undefined ? undefined : requiredModule(p.get('object') as NodePath);
      return from && name !== undefined ? { from, name } : undefined;
    }
    if (!p.isIdentifier()) return undefined;
    const b = p.scope.getBinding(p.node.name);
    const decl = b?.path.node;
    if (!b || !decl) return undefined;
    if (decl.type === 'ImportSpecifier' || decl.type === 'ImportDefaultSpecifier') {
      const from = moduleAt(b.path, bindingModule(b));
      return from ? { from, name: decl.type === 'ImportDefaultSpecifier' ? 'default' : importedName(b) } : undefined;
    }
    if (decl.type === 'VariableDeclarator' && decl.id.type === 'ObjectPattern') {
      const from = moduleAt(b.path, moduleOfInit(decl.init, b.scope));
      return from ? { from, name: importedName(b) } : undefined;
    }
    return undefined;
  };

  /** The class whose instance `p` is: `new X()`, or a never-reassigned constant holding one. */
  function instanceClass(p: NodePath): NodePath | undefined {
    const direct = classOfNew(p);
    if (direct || !p.isIdentifier()) return direct;
    const b = p.scope.getBinding(p.node.name);
    if (!b?.constant || !b.path.isVariableDeclarator()) return undefined;
    return classOfNew(b.path.get('init') as NodePath);
  }

  /** The object literal a never-reassigned constant holds (`const h = { run() {…} }; export default h`). */
  const constObject = (p: NodePath): NodePath | undefined => {
    if (p.isObjectExpression()) return p;
    if (!p.isIdentifier()) return undefined;
    const b = p.scope.getBinding(p.node.name);
    if (!b?.constant || !b.path.isVariableDeclarator()) return undefined;
    const init = b.path.get('init') as NodePath;
    return init.isObjectExpression() ? init : undefined;
  };

  /** `exports`, `module.exports` (not a local named `exports`). */
  const isExportsObject = (node: Node, scope: Scope): boolean =>
    isModuleExports(node) || (node.type === 'Identifier' && node.name === 'exports' && !scope.getBinding('exports'));

  /** A file's export table: ES exports, CommonJS `module.exports`/`exports.f`, re-exports. One walk of its top-level statements. */
  const exportsOf = (file: ModuleFile): Map<string, ExportEntry> => {
    if (file.exports) return file.exports;
    const table = new Map<string, ExportEntry>();
    const stars: ModuleFile[] = [];
    file.exports = table;
    file.stars = stars;
    const set = (name: string | undefined, entry: ExportEntry | undefined): void => {
      if (name !== undefined && entry && !table.has(name)) table.set(name, entry);
    };
    const setObject = (prefix: string, object: NodePath): void => {
      for (const prop of object.get('properties') as NodePath[]) {
        if (prop.isObjectMethod()) set(prefix + (keyName(prop.node.key, prop.node.computed) ?? ''), { fn: prop });
        else if (prop.isObjectProperty()) {
          const name = keyName(prop.node.key, prop.node.computed);
          if (name !== undefined) set(prefix + name, exportEntry(prop.get('value') as NodePath));
        }
      }
    };
    let program: NodePath | undefined;
    traverse(file.ast, { Program(p) { program = p; p.stop(); } });
    for (const stmt of (program?.get('body') ?? []) as NodePath[]) {
      if (stmt.isExportNamedDeclaration()) {
        const decl = stmt.get('declaration');
        if (decl.isFunctionDeclaration() && decl.node.id) set(decl.node.id.name, { fn: decl });
        else if (decl.isVariableDeclaration()) {
          for (const d of decl.get('declarations')) {
            if (d.node.id.type === 'Identifier') set(d.node.id.name, exportEntry(d.get('init') as NodePath));
          }
        }
        const source = stmt.node.source?.value;
        const from = source !== undefined ? moduleAt(stmt, source) : undefined;
        for (const spec of stmt.get('specifiers')) {
          if (!spec.isExportSpecifier()) continue;
          const name = keyName(spec.node.exported);
          if (name === undefined) continue;
          if (source === undefined) set(name, exportEntry(spec.get('local')));
          else if (from) set(name, { from, name: spec.node.local.name });
        }
      } else if (stmt.isExportDefaultDeclaration()) {
        const decl = stmt.get('declaration') as NodePath;
        const object = constObject(decl);
        if (object) setObject('default.', object);
        else set('default', exportEntry(decl));
      } else if (stmt.isExportAllDeclaration()) {
        const from = moduleAt(stmt, stmt.node.source.value);
        if (from) stars.push(from);
      } else if (stmt.isExpressionStatement()) {
        const e = stmt.get('expression');
        if (e.isCallExpression()) {
          const name = calleeName(e.node.callee as Node);
          const args = e.get('arguments') as NodePath[];
          // TypeScript's `__exportStar(require("./h"), exports)`, esbuild's `__reExport(x, require("./h"))`
          if (name === '__exportStar' || name === '__reExport') {
            for (const a of args) {
              const from = moduleAt(stmt, moduleOfInit(a.node, a.scope));
              if (from) stars.push(from);
            }
          } else if (name === 'defineProperty' && args.length >= 3 && isExportsObject(args[0].node, e.scope) && args[2].isObjectExpression()) {
            // `Object.defineProperty(exports, "run", { get: function () { return h_1.run; } })`, `{ value: run }`
            const exportName = staticString(args[1].node, args[1].scope);
            for (const prop of args[2].get('properties') as NodePath[]) {
              const key = prop.isObjectProperty() || prop.isObjectMethod() ? keyName(prop.node.key, prop.node.computed) : undefined;
              if (key === 'value' && prop.isObjectProperty()) set(exportName, exportEntry(prop.get('value') as NodePath));
              if (key !== 'get') continue;
              const getter = prop.isObjectMethod() ? prop : prop.isObjectProperty() ? functionAt(prop.get('value') as NodePath) : undefined;
              const body = getter?.get('body') as NodePath | undefined;
              const returned = body?.isBlockStatement() ? (body.get('body') as NodePath[]).find((s) => s.isReturnStatement())?.get('argument') as NodePath | undefined : body;
              set(exportName, exportEntry(returned));
            }
          }
          continue;
        }
        if (!e.isAssignmentExpression({ operator: '=' })) continue;
        const left = e.node.left;
        const right = e.get('right');
        if (isModuleExports(left)) {
          // module.exports = { run, check() {} } / = run / = require('./impl') / = h (a constant object)
          const object = constObject(right);
          if (object) setObject('', object);
          else {
            const from = moduleAt(stmt, moduleOfInit(right.node, right.scope));
            if (from) stars.push(from);
            else set('default', exportEntry(right));
          }
        } else if (left.type === 'MemberExpression' && isExportsObject(left.object, e.scope)) {
          // exports.run = run / module.exports.run = function (…) {…} / exports.run = h_1.run
          set(memberName(left), exportEntry(right));
        }
      }
    }
    return table;
  };

  /** The function a module exports under `name`, through re-exports; memoized, cycles end. */
  const exported = new Map<ModuleFile, Map<string, NodePath | null>>();
  const lookup = (file: ModuleFile, name: string, depth = 0): NodePath | undefined => {
    let known = exported.get(file);
    if (!known) exported.set(file, (known = new Map()));
    if (known.has(name)) return known.get(name) ?? undefined;
    if (depth > MAX_DEPTH) return undefined;
    known.set(name, null); // a re-export cycle exports nothing more
    const entry = exportsOf(file).get(name);
    let fn: NodePath | undefined;
    if (entry) fn = 'fn' in entry ? entry.fn : 'cls' in entry ? undefined : lookup(entry.from, entry.name, depth + 1);
    else if (name !== 'default' && !name.startsWith('default.')) {
      for (const star of file.stars ?? []) if ((fn = lookup(star, name, depth + 1))) break;
    }
    known.set(name, fn ?? null);
    return fn;
  };

  /** The class of the instance a module exports under `name`, through re-exports; cycles end. */
  const exportedClasses = new Map<ModuleFile, Map<string, NodePath | null>>();
  const lookupClass = (file: ModuleFile, name: string, depth = 0): NodePath | undefined => {
    let known = exportedClasses.get(file);
    if (!known) exportedClasses.set(file, (known = new Map()));
    if (known.has(name)) return known.get(name) ?? undefined;
    if (depth > MAX_DEPTH) return undefined;
    known.set(name, null);
    const entry = exportsOf(file).get(name);
    let cls: NodePath | undefined;
    if (entry) cls = 'cls' in entry ? entry.cls : 'from' in entry ? lookupClass(entry.from, entry.name, depth + 1) : undefined;
    else if (name !== 'default') {
      for (const star of file.stars ?? []) if ((cls = lookupClass(star, name, depth + 1))) break;
    }
    known.set(name, cls ?? null);
    return cls;
  };

  /** The module of the group an identifier names: a namespace or default import, or a CommonJS `require` binding. */
  const moduleOfName = (id: NodePath): ModuleFile | undefined => {
    if (!id.isIdentifier()) return undefined;
    const b = id.scope.getBinding(id.node.name);
    const decl = b?.path.node;
    if (!b || !decl) return undefined;
    if (decl.type === 'ImportNamespaceSpecifier' || decl.type === 'ImportDefaultSpecifier') return moduleAt(b.path, bindingModule(b));
    return requiredModule(id);
  };

  /**
   * The class of the object a method is called on: a local `new X()`, an
   * instance another module of the group exports (`import { tm } from
   * './tm.js'`, `const { tm } = require('./tm')`, `tm_1.tm` in TypeScript's
   * CommonJS output, `ns.tm` of a namespace import).
   */
  const receiverClass = (object: NodePath): NodePath | undefined => {
    if (object.isIdentifier()) {
      const local = instanceClass(object);
      if (local || !linked) return local;
      const b = object.scope.getBinding(object.node.name);
      const decl = b?.path.node;
      if (!b || !decl) return undefined;
      if (decl.type === 'ImportSpecifier' || decl.type === 'ImportDefaultSpecifier') {
        const from = moduleAt(b.path, bindingModule(b));
        return from && lookupClass(from, decl.type === 'ImportDefaultSpecifier' ? 'default' : importedName(b));
      }
      if (decl.type === 'VariableDeclarator' && decl.id.type === 'ObjectPattern') {
        const from = moduleAt(b.path, moduleOfInit(decl.init, b.scope));
        return from && lookupClass(from, importedName(b));
      }
      return undefined;
    }
    if (!linked || !(object.isMemberExpression() || object.isOptionalMemberExpression())) return undefined;
    const name = memberName(object.node);
    const from = name === undefined ? undefined : moduleOfName(object.get('object') as NodePath);
    return from && name !== undefined ? lookupClass(from, name) : undefined;
  };

  /** The method a call on a class instance invokes (`tm.executeCommand(cmd)`), when the instance's class is known. */
  const instanceMethod = (path: NodePath): NodePath | undefined => {
    if (!path.isCallExpression() && !path.isOptionalCallExpression()) return undefined;
    const callee = path.get('callee') as NodePath;
    if (!(callee.isMemberExpression() || callee.isOptionalMemberExpression())) return undefined;
    const name = keyName(callee.node.property as Node, callee.node.computed);
    if (name === undefined) return undefined;
    const cls = receiverClass(callee.get('object') as NodePath);
    return cls ? classMethod(cls, name) : undefined;
  };

  /**
   * The functions a computed call may reach (`handlers[name](args)`): every
   * function of a constant object literal, or every function a namespace
   * import of the group exports.
   */
  const dispatchTargets = (path: NodePath): Node[] => {
    if (!path.isCallExpression()) return [];
    const callee = path.get('callee') as NodePath;
    if (!callee.isMemberExpression() || !callee.node.computed || callee.get('property').isStringLiteral()) return [];
    const object = callee.get('object') as NodePath;
    const out: Node[] = [];
    const literal = constObject(object);
    if (literal) {
      for (const prop of literal.get('properties') as NodePath[]) {
        if (out.length >= MAX_DISPATCH_TARGETS) break;
        const fn = prop.isObjectMethod() ? prop : prop.isObjectProperty() ? functionAt(prop.get('value') as NodePath) ?? importedFunction(prop, prop.node.value as Node) : undefined;
        if (fn) out.push(fn.node);
      }
      return out;
    }
    const from = linked ? moduleOfName(object) : undefined;
    if (!from) return [];
    for (const name of exportsOf(from).keys()) {
      if (out.length >= MAX_DISPATCH_TARGETS) break;
      const fn = lookup(from, name);
      if (fn) out.push(fn.node);
    }
    return out;
  };

  /**
   * The function of another module of the group that `node` (a callee or a
   * handler reference, seen from `path`) names: `run` from `import { run }`,
   * `import run from`, `const { run } = require(…)`; `h.run` from `import * as
   * h`, `import h from`, `const h = require(…)`; `require('./h').run`; and
   * TypeScript's CommonJS output `(0, h_1.run)(…)`.
   */
  const importedFunction = (path: NodePath, node: Node | undefined): NodePath | undefined => {
    if (!linked || !node) return undefined;
    if (node.type === 'SequenceExpression') node = node.expressions[node.expressions.length - 1];
    if (node.type === 'Identifier') {
      const b = path.scope.getBinding(node.name);
      const decl = b?.path.node;
      if (!b || !decl) return undefined;
      if (decl.type === 'ImportSpecifier' || decl.type === 'ImportDefaultSpecifier') {
        const from = moduleAt(b.path, bindingModule(b));
        return from && lookup(from, decl.type === 'ImportDefaultSpecifier' ? 'default' : importedName(b));
      }
      if (decl.type !== 'VariableDeclarator') return undefined;
      const from = moduleAt(b.path, moduleOfInit(decl.init, b.scope));
      if (!from) return undefined;
      return decl.id.type === 'ObjectPattern' ? lookup(from, importedName(b)) : lookup(from, 'default');
    }
    if (node.type !== 'MemberExpression' && node.type !== 'OptionalMemberExpression') return undefined;
    const name = memberName(node);
    if (name === undefined) return undefined;
    const object = node.object;
    let from: ModuleFile | undefined;
    let viaDefault = false;
    if (object.type === 'Identifier') {
      const b = path.scope.getBinding(object.name);
      const decl = b?.path.node;
      if (!b || !decl) return undefined;
      if (decl.type === 'ImportNamespaceSpecifier' || decl.type === 'ImportDefaultSpecifier') {
        from = moduleAt(b.path, bindingModule(b));
        viaDefault = decl.type === 'ImportDefaultSpecifier';
      } else if (decl.type === 'VariableDeclarator' && decl.id.type === 'Identifier') {
        from = moduleAt(b.path, moduleOfInit(decl.init, b.scope));
      }
    } else {
      from = moduleAt(path, moduleOfInit(object, path.scope));
    }
    if (!from) return undefined;
    // A default import of CommonJS is its module.exports: `h.run` is the export `run`
    return viaDefault
      ? lookup(from, `default.${name}`) ?? lookup(from, name)
      : lookup(from, name) ?? lookup(from, `default.${name}`);
  };

  // Pass 1: functions registered as tool/request handlers — all their
  // parameters carry tool input.
  const handlers = new WeakSet<Node>();
  // Input fields each handler's schema limits to fixed choices or numbers (`z.enum`, `z.number`)
  const constrainedInputs = new WeakMap<Node, Set<string>>();
  // Parameters (by position) of functions that are called with tool input.
  const taintedParams = new WeakMap<Node, Set<number>>();

  for (const file of files) {
    safely(() => traverse(file.ast, {
      CallExpression(path) {
        const { callee, arguments: args } = path.node;
        // `server.tool(…)`, also written `server["tool"](…)`
        if (callee.type !== 'MemberExpression') return;
        const registrar = keyName(callee.property, callee.computed);
        if (registrar === undefined || !HANDLER_REGISTRARS.has(registrar)) return;
        // Inline, by reference (`server.tool("t", "d", {}, handleIt)`, also
        // imported from another module), or FastMCP-TS's `addTool({ name, execute })`.
        const constrained = constrainedSchemaFields(args as Node[]);
        const addHandler = (node: Node | undefined): void => {
          const fn = functionNode(path, node) ?? importedFunction(path, node)?.node;
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
    }));
  }

  {
    // What a value carries is worked out once, symbolically: tool input
    // (`origin`), or the parameters of the functions it comes from (`deps`),
    // whatever their callers pass. A parameter is tool input when some call
    // site passes tool input there (taintedParams, Pass 1b). A call's return
    // value carries what that call's own arguments carry: a helper that
    // returns its argument cleaned up (`norm(s)`) carries tool input where a
    // handler calls it with input, not where startup code calls it with a
    // constant.
    const memo = new Map<Binding, Taint | null>();

    const bindingTaint = (binding: Binding, depth: number): Taint => {
      const known = memo.get(binding);
      if (known !== undefined) return known ?? CLEAN;
      memo.set(binding, null); // cycle guard
      let taint = CLEAN;
      const name = binding.identifier.name;

      if (binding.kind === 'param') {
        const fn = binding.scope.block;
        if (handlers.has(fn) || INPUT_NAMES.has(name)) {
          taint = { origin: name, deps: [] };
        } else if (fn.type.includes('Function') || fn.type === 'ClassMethod' || fn.type === 'ObjectMethod') {
          const params = (fn as { params?: Node[] }).params ?? [];
          const id = binding.identifier;
          const index = params.findIndex((p) => (p.start ?? -1) <= (id.start ?? 0) && (id.end ?? 0) <= (p.end ?? -1));
          if (index !== -1) taint = { deps: [{ fn, index, chain: name }] };
        }
      } else if (depth < MAX_DEPTH && (binding.kind === 'const' || binding.kind === 'let' || binding.kind === 'var')) {
        const declarator = binding.path;
        if (declarator.isVariableDeclarator()) {
          const init = declarator.get('init');
          if (init.node) taint = expressionTaint(init as NodePath, depth + 1);
          // `for (const c of cmds)`, `for (const k in input)`: the loop variable holds the iterable's elements or keys
          const loop = declarator.parentPath?.parentPath;
          if (!init.node && (loop?.isForOfStatement() || loop?.isForInStatement()) && loop.node.left === declarator.parent) {
            taint = expressionTaint(loop.get('right') as NodePath, depth + 1);
          }
        }
        for (const violation of binding.constantViolations) {
          if (taint.origin) break;
          if (violation.isAssignmentExpression()) taint = mergeTaint(taint, expressionTaint(violation.get('right'), depth + 1));
        }
        // what is stored on it: `opts.command = cmd`, `o[k] = v`
        for (const { right } of memberStores(binding)) {
          if (taint.origin) break;
          taint = mergeTaint(taint, expressionTaint(right, depth + 1));
        }
        taint = renamed(name, taint);
      }

      memo.set(binding, taint);
      return taint;
    };

    /**
     * Assignments to a property of the object a binding holds (`o.x = v`,
     * `o[k] = v`): `prop` undefined for a computed key.
     */
    const stores = new Map<Binding, Array<{ prop?: string; right: NodePath }>>();
    function memberStores(binding: Binding): Array<{ prop?: string; right: NodePath }> {
      let out = stores.get(binding);
      if (out) return out;
      out = [];
      for (const ref of binding.referencePaths) {
        const member = ref.parentPath;
        if (!member?.isMemberExpression() || member.node.object !== ref.node) continue;
        const assign = member.parentPath;
        if (!assign?.isAssignmentExpression({ operator: '=' }) || assign.node.left !== member.node) continue;
        out.push({ prop: keyName(member.node.property, member.node.computed), right: assign.get('right') });
      }
      stores.set(binding, out);
      return out;
    }

    /**
     * What `o.prop` carries when `o` is a local object literal never
     * reassigned, read field by field: the literal's `prop` and what is
     * stored under that name (or a computed key). Undefined when a spread or
     * computed key makes its fields unknown — the object is then read whole.
     */
    const propertyTaint = (m: NodePath, depth: number): Taint | undefined => {
      if (!m.isMemberExpression() || m.node.object.type !== 'Identifier') return undefined;
      // a method called on it (`o.toString()`) reads the whole object
      if (m.parentPath?.isCallExpression() && m.parent.type === 'CallExpression' && (m.parent as { callee: Node }).callee === m.node) return undefined;
      const prop = keyName(m.node.property, m.node.computed);
      if (prop === undefined) return undefined;
      const b = m.scope.getBinding(m.node.object.name);
      if (!b || b.constantViolations.length > 0 || !b.path.isVariableDeclarator()) return undefined;
      const init = b.path.get('init') as NodePath;
      if (!init.isObjectExpression()) return undefined;
      // memoized per object and field, like bindingTaint; a cycle reads nothing more
      let fields = fieldMemo.get(b);
      if (!fields) fieldMemo.set(b, (fields = new Map()));
      if (fields.has(prop)) return fields.get(prop) ?? CLEAN;
      const props = init.get('properties') as NodePath[];
      for (const p of props) {
        if (!p.isObjectProperty() && !p.isObjectMethod()) return undefined;
        if (keyName(p.node.key, p.node.computed) === undefined) return undefined;
      }
      fields.set(prop, null);
      let taint = CLEAN;
      for (const p of props) {
        if (p.isObjectProperty() && keyName(p.node.key, p.node.computed) === prop) taint = mergeTaint(taint, expressionTaint(p.get('value') as NodePath, depth + 1));
      }
      for (const st of memberStores(b)) {
        if (taint.origin) break;
        if (st.prop === undefined || st.prop === prop) taint = mergeTaint(taint, expressionTaint(st.right, depth + 1));
      }
      fields.set(prop, taint);
      return taint;
    };
    const fieldMemo = new Map<Binding, Map<string, Taint | null>>();

    /** What tool input `path` may carry: every input-derived identifier it references, up to the first certain one. */
    const expressionTaint = (path: NodePath, depth: number): Taint => {
      // A number derived from input (`actions.length`, `Number(x)`) can't
      // carry a path, a query or a command
      if (yieldsNumber(path)) return CLEAN;
      const field = depth < MAX_DEPTH ? propertyTaint(path, depth) : undefined;
      if (field) return field;
      const local = localFunctionCall(path);
      if (local) return callTaint(path, local, depth);
      let found = CLEAN;
      const visit = (id: NodePath): void => {
        if (!id.isIdentifier() || !id.isReferencedIdentifier()) return;
        const binding = id.scope.getBinding(id.node.name);
        if (!binding) {
          if (INPUT_NAMES.has(id.node.name)) found = mergeTaint(found, { origin: id.node.name, deps: [] });
          return;
        }
        const t = bindingTaint(binding, depth);
        // `if (!ALLOWED.includes(c)) throw …` before this use: `c` is one of fixed values here
        if (isClean(t) || (binding.scope.path.isFunction() && guardedBefore(id, binding))) return;
        found = mergeTaint(found, t);
      };
      visit(path);
      if (found.origin) return found;
      path.traverse({
        Identifier(id) {
          if (found.origin) return id.stop();
          visit(id);
        },
        // A nested function's body doesn't flow into this value.
        Function(fn) { fn.skip(); },
        MemberExpression(m) {
          if (yieldsNumber(m)) return m.skip();
          const field = depth < MAX_DEPTH ? propertyTaint(m, depth) : undefined;
          if (field) {
            found = mergeTaint(found, field);
            m.skip();
          }
        },
        CallExpression(c) {
          if (found.origin) return c.stop();
          if (yieldsNumber(c)) return c.skip();
          // A call to a function of the group carries what it returns for these arguments
          const fn = localFunctionCall(c);
          if (fn) {
            found = mergeTaint(found, callTaint(c, fn, depth));
            c.skip();
          }
        },
      });
      return found;
    };

    /** The function a call invokes, when it is declared in this file or exported by another module of the group. */
    const localFunctionCall = (path: NodePath): NodePath | undefined => {
      if (!path.isCallExpression()) return undefined;
      const callee = path.get('callee');
      if (!callee.isIdentifier()) return importedFunction(path, callee.node) ?? instanceMethod(path);
      const binding = path.scope.getBinding(callee.node.name);
      if (!binding) return undefined;
      if (binding.path.isFunctionDeclaration()) return binding.path;
      if (binding.path.isVariableDeclarator()) {
        const init = binding.path.get('init');
        if (init.isFunctionExpression() || init.isArrowFunctionExpression()) return init;
      }
      return importedFunction(path, callee.node);
    };

    /**
     * What a call of `fn` returns at this call site: what its returns carry,
     * with its own parameters replaced by the arguments given here.
     */
    const callTaint = (call: NodePath, fn: NodePath, depth: number): Taint => {
      const summary = returnSummary(fn);
      if (isClean(summary)) return CLEAN;
      const name = (fn.node as { id?: { name?: string } }).id?.name ?? 'function';
      let out: Taint = summary.origin ? { origin: `${name}() ← ${summary.origin}`, deps: [] } : CLEAN;
      const args = call.get('arguments') as NodePath[];
      for (const dep of summary.deps) {
        if (out.origin) break;
        if (dep.fn !== fn.node) {
          // a parameter of an enclosing function the helper closes over
          out = mergeTaint(out, { deps: [{ ...dep, chain: `${name}() ← ${dep.chain}` }] });
          continue;
        }
        const arg = argumentAt(args, dep.index);
        if (!arg || depth >= MAX_DEPTH) continue;
        const given = expressionTaint(arg, depth + 1);
        if (isClean(given)) continue;
        const via = `${name}() ← ${dep.chain}`;
        out = mergeTaint(out, {
          ...(given.origin ? { origin: `${via} ← ${given.origin}` } : {}),
          deps: given.deps.map((d) => ({ ...d, chain: `${via} ← ${d.chain}` })),
        });
      }
      return out;
    };

    /**
     * What a function's return values carry, in terms of its parameters.
     * Memoized per function (recomputing it at every call site was
     * exponential in call depth); a function being summarized returns
     * nothing new through itself.
     */
    const summaries = new Map<Node, Taint | null>();
    let nesting = 0;
    const returnSummary = (fn: NodePath): Taint => {
      const known = summaries.get(fn.node);
      if (known !== undefined) return known ?? CLEAN;
      if (nesting >= MAX_SUMMARY_NESTING) return CLEAN;
      summaries.set(fn.node, null);
      nesting++;
      let summary = CLEAN;
      try {
        if (fn.isArrowFunctionExpression() && !fn.get('body').isBlockStatement()) {
          summary = expressionTaint(fn.get('body') as NodePath, 0);
        } else {
          fn.traverse({
            Function(inner) { inner.skip(); },
            ReturnStatement(r) {
              if (summary.origin) return r.stop();
              const arg = r.get('argument');
              if (arg.node) summary = mergeTaint(summary, expressionTaint(arg as NodePath, 0));
            },
          });
        }
      } finally {
        nesting--;
      }
      summaries.set(fn.node, summary);
      return summary;
    };

    /** A taint made concrete: tool input, or a parameter some call site passes tool input to. */
    const resolveTaint = (t: Taint): string | undefined => {
      if (t.origin) return t.origin;
      for (const d of t.deps) if (taintedParams.get(d.fn)?.has(d.index)) return `${d.chain} ← caller`;
      return undefined;
    };

    /** Where `path`'s value comes from: tool input, or (`unverified`) what an untraced module's export receives. */
    const sinkOrigin = (path: NodePath): { origin: string; unverified?: true } | undefined => {
      const t = expressionTaint(path, 0);
      const origin = resolveTaint(t);
      if (origin) return { origin };
      for (const d of t.deps) if (unknownParams.get(d.fn)?.has(d.index)) return { origin: `${d.chain} ← caller not traced`, unverified: true };
      return undefined;
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
      const tainted = built.parts.filter((p) => p.path.node && !sqlSafePiece(p.path, constrainedInput, 0, p.quote) && sinkOrigin(p.path));
      if (tainted.length === 0) return;
      const found = tainted.map((p) => sinkOrigin(p.path)!);
      const { origin, unverified } = found.find((f) => !f.unverified) ?? found[0];
      const line = path.node.loc?.start.line ?? 0;
      pushResult(line, {
        sink: `${shown}.${prop}`, origin, kind: 'query',
        ...(tainted.every((p) => p.wraps) ? { wrapsStatement: true } : {}),
        ...(unverified ? { unverified } : {}),
      });
    };

    const report = (path: NodePath<Node>, sink: string, candidates: NodePath[], kind: SinkKind): void => {
      let maybe: string | undefined;
      for (const arg of candidates) {
        if (!arg.node) continue;
        const found = sinkOrigin(arg);
        if (found && !found.unverified) {
          pushResult(path.node.loc?.start.line ?? 0, { sink, origin: found.origin, kind });
          return;
        }
        maybe ??= found?.origin;
      }
      if (maybe) pushResult(path.node.loc?.start.line ?? 0, { sink, origin: maybe, kind, unverified: true });
    };

    // Pass 1b: carry tool input into functions through their call sites
    // (`this.getFolderSize(request.params.arguments)` taints `getFolderSize(args)`,
    // `runQuery(args.sql)` taints the `runQuery` another module exports). One
    // walk records, per call site argument, what it carries: tool input taints
    // the callee's parameter at once; a parameter of the caller is an edge
    // (caller param → callee param). Tool input then spreads along the edges
    // to a fixpoint — handler → helper → helper chains of any length, in any
    // order of declaration.
    const flowsTo = new Map<Node, Map<number, Array<[Node, number]>>>();
    const reached: Array<[Node, number]> = [];
    let edges = 0;
    const taintParam = (fn: Node, index: number): void => {
      const set = taintedParams.get(fn) ?? new Set<number>();
      if (set.has(index)) return;
      set.add(index);
      taintedParams.set(fn, set);
      reached.push([fn, index]);
    };
    /** What `t` carries reaches parameter `index` of each of `targets`. */
    const flowInto = (t: Taint, targets: Node[], index: number): void => {
      for (const target of targets) {
        if (t.origin) {
          taintParam(target, index);
          continue;
        }
        for (const d of t.deps) {
          if (edges >= MAX_FLOW_EDGES) return;
          let byIndex = flowsTo.get(d.fn);
          if (!byIndex) flowsTo.set(d.fn, (byIndex = new Map()));
          const list = byIndex.get(d.index) ?? [];
          if (list.length === 0) byIndex.set(d.index, list);
          list.push([target, index]);
          edges++;
        }
      }
    };
    const visitCalls = {
      CallExpression(path: NodePath) {
        const callee = (path.node as { callee: Node }).callee;
        // `cmds.forEach((c) => exec(c))`: the callback's parameter holds the receiver's elements
        if (callee.type === 'MemberExpression' && !callee.computed && callee.property.type === 'Identifier' && callee.property.name in ELEMENT_CALLBACKS) {
          const cb = functionAt((path.get('arguments') as NodePath[])[0]);
          if (cb) {
            const t = expressionTaint(path.get('callee.object') as NodePath, 0);
            if (!isClean(t)) flowInto(t, [cb.node], ELEMENT_CALLBACKS[callee.property.name]);
          }
        }
        const imported = importedFunction(path, callee);
        const method = imported ? undefined : instanceMethod(path);
        const targets = [...localCallees(path), ...(imported ? [imported.node] : []), ...(method ? [method.node] : []), ...dispatchTargets(path)];
        if (targets.length === 0) return;
        const args = path.get('arguments') as NodePath[];
        args.forEach((arg, index) => {
          if (!arg.node) return;
          const t = expressionTaint(arg, 0);
          if (isClean(t)) return;
          flowInto(t, targets, index);
        });
      },
    };
    for (const file of files) safely(() => traverse(file.ast, visitCalls));
    for (let i = 0; i < reached.length; i++) {
      const [fn, index] = reached[i];
      for (const [target, at] of flowsTo.get(fn)?.get(index) ?? []) taintParam(target, at);
    }

    // Modules a tool handler's file imports that its group left out (size
    // cap): the parameters of what they export may receive tool input
    // nobody traced. Spread like tool input, kept apart: a sink they reach is
    // "not verified", not tool input.
    const unknownParams = new WeakMap<Node, Set<number>>();
    const unknown: Array<[Node, number]> = [];
    const markUnknown = (fn: Node, index: number): void => {
      if (taintedParams.get(fn)?.has(index)) return;
      const set = unknownParams.get(fn) ?? new Set<number>();
      if (set.has(index)) return;
      set.add(index);
      unknownParams.set(fn, set);
      unknown.push([fn, index]);
    };
    for (const file of files) {
      if (!file.chunk.path || !untraced.has(file.chunk.path)) continue;
      safely(() => {
        for (const name of exportsOf(file).keys()) {
          const fn = lookup(file, name)?.node as { params?: Node[] } | undefined;
          fn?.params?.forEach((_, i) => markUnknown(fn as Node, i));
        }
      });
    }
    for (let i = 0; i < unknown.length; i++) {
      const [fn, index] = unknown[i];
      for (const [target, at] of flowsTo.get(fn)?.get(index) ?? []) markUnknown(target, at);
    }

    // Pass 2: sinks.
    const visitSinks = {
      'CallExpression|NewExpression'(path: NodePath) {
        if (!path.isCallExpression() && !path.isNewExpression()) return;
        const callee = path.node.callee;
        const args = path.get('arguments') as NodePath[];

        const exec = sinkCallee(path);
        if (exec) {
          // `new Function(code);` with the result discarded compiles the code
          // (a syntax check), never runs it
          if (exec.fn === 'Function' && !exec.display.startsWith('._compile') && path.parentPath?.isExpressionStatement()) return;
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
    };
    for (const file of files) {
      current = file;
      safely(() => traverse(file.ast, visitSinks));
    }
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
/**
 * An interpolated piece of SQL text: `wraps`, it is the whole statement in
 * parentheses; `quote`, the `'…'` or `"…"` literal of the text it sits inside.
 */
interface SqlPart {
  path: NodePath;
  wraps: boolean;
  quote?: SqlQuote;
}
type SqlQuote = "'" | '"';

/** The quote the SQL text before a piece leaves open (`''` / `""` escapes count twice), if any. */
function openQuote(before: string): SqlQuote | undefined {
  let open: SqlQuote | undefined;
  for (let i = 0; i < before.length; i++) {
    const c = before[i];
    if (c !== "'" && c !== '"') continue;
    if (open === undefined) open = c;
    else if (c === open) open = undefined;
  }
  return open;
}

/** `{ quote }` for a piece after `before`, or nothing. */
function quoteOf(before: string): { quote?: SqlQuote } {
  const quote = openQuote(before);
  return quote ? { quote } : {};
}

function sqlPieces(arg: NodePath, sql: RegExp, depth = 0): { parts: SqlPart[] } | undefined {
  if (depth > 3) return undefined;
  const fromOperands = (operands: NodePath[], sep = ''): { parts: SqlPart[] } | undefined => {
    const texts = operands.map((p) => staticString(p.node, p.scope));
    const text = texts.map((t) => t ?? ' ').join(sep || '');
    if (!sql.test(text)) return undefined;
    const parts: SqlPart[] = [];
    let before = '';
    operands.forEach((path, i) => {
      if (i > 0) before += sep;
      const fixedText = texts[i];
      if (fixedText !== undefined) before += fixedText;
      else parts.push({ path, wraps: false, ...quoteOf(before) });
    });
    return { parts };
  };
  if (arg.isTemplateLiteral()) {
    const quasis = arg.node.quasis.map((q) => q.value.cooked ?? q.value.raw);
    if (!sql.test(quasis.join(' '))) return undefined;
    const expressions = arg.get('expressions') as NodePath[];
    return {
      parts: expressions.map((path, i) => ({
        path,
        wraps: WRAP_BEFORE.test(quasis[i] ?? '') && /^\s*(?:\)|$)/.test(quasis[i + 1] ?? ''),
        ...quoteOf(quasis.slice(0, i + 1).join('')),
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
function formatPieces(args: NodePath[], sql: RegExp): { parts: SqlPart[] } | undefined {
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
/** Escapers that quote an identifier, not a value: unsafe inside a `'…'` literal. */
const SQL_IDENTIFIER_ESCAPES = /^(?:escapeId|escapeIdentifier|quoteIdent|quoteIdentifier|quote_ident)$/;
/** pg-format's escaping members (`format.literal(x)`). */
const PG_FORMAT_ESCAPES = /^(?:literal|ident|string)$/;
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
function sqlSafePiece(path: NodePath, constrained: (path: NodePath) => boolean, depth = 0, quote?: SqlQuote): boolean {
  if (depth > 4 || !path.node) return false;
  if (constrained(path)) return true;
  if (path.isIdentifier()) {
    const binding = path.scope.getBinding(path.node.name);
    if (binding && guardedBefore(path, binding)) return true;
    if (!binding?.constant || !binding.path.isVariableDeclarator()) return false;
    const init = binding.path.get('init') as NodePath;
    return !!init.node && sqlSafePiece(init, constrained, depth + 1, quote);
  }
  if (path.isConditionalExpression()) return allowListChoice(path);
  // `COLUMNS[name] ?? "id"`: a lookup in a table of fixed values, with a fixed fallback
  if (path.isLogicalExpression() && (path.node.operator === '??' || path.node.operator === '||')) {
    const fixedOr = (p: NodePath): boolean => staticString(p.node, p.scope) !== undefined || p.isNumericLiteral() || sqlSafePiece(p, constrained, depth + 1, quote);
    return fixedOr(path.get('left') as NodePath) && fixedOr(path.get('right') as NodePath);
  }
  if (path.isMemberExpression() && path.node.computed) return fixedList(path.node.object, path.scope, 0, true);
  if (path.isTemplateLiteral()) {
    return (path.get('expressions') as NodePath[]).every((e) => sqlSafePiece(e, constrained, depth + 1, quote));
  }
  if (!path.isCallExpression()) return false;
  const callee = path.get('callee');
  const name = callee.isIdentifier() ? callee.node.name
    : callee.isMemberExpression() && !callee.node.computed && callee.node.property.type === 'Identifier' ? callee.node.property.name : '';
  // Inside a `'…'` literal only a value escaper keeps it closed: an
  // identifier escaper (`escapeId`) leaves `'` as it is. MySQL reads `"…"` as
  // a string literal too (ANSI_QUOTES is off by default), which its escapeId
  // leaves open the same way
  const quoted = quote === "'" || (quote === '"' && name === 'escapeId');
  if (SQL_ESCAPES.test(name) && !(quoted && SQL_IDENTIFIER_ESCAPES.test(name)) && sqlEscapeCall(callee as NodePath)) return true;
  // pg-format's `format.literal(x)` / `format.ident(x)` / `format.string(x)`
  if (PG_FORMAT_ESCAPES.test(name) && !(quote === "'" && name === 'ident') && callee.isMemberExpression()) {
    const holder = callee.get('object') as NodePath;
    if (holder.isIdentifier() && bindingModule(holder.scope.getBinding(holder.node.name)) === 'pg-format') return true;
  }
  if (name === 'format') {
    const holder = callee.isIdentifier() ? callee : callee.isMemberExpression() ? callee.get('object') as NodePath : undefined;
    // a fixed format string and values to put in it: `mysql.format(x)` alone returns `x`
    const args = path.get('arguments') as NodePath[];
    if (holder?.isIdentifier() && SQL_FORMAT_MODULES.test(bindingModule(holder.scope.getBinding(holder.node.name)) ?? holder.node.name)
      && args.length >= 2 && staticString(args[0].node, args[0].scope) !== undefined) return true;
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

/** A statement that always leaves: `throw …`, `return …`, or a block ending in one. */
function alwaysExits(node: Node): boolean {
  if (node.type === 'ThrowStatement' || node.type === 'ReturnStatement') return true;
  return node.type === 'BlockStatement' && node.body.length > 0 && alwaysExits(node.body[node.body.length - 1]);
}

/** `x = "asc"` (also alone in a block): the assignment of a fixed value to `name`, or undefined. */
function fixedReassignment(node: Node, name: string, scope: Scope): Node | undefined {
  const stmt = node.type === 'BlockStatement' && node.body.length === 1 ? node.body[0] : node;
  if (stmt.type !== 'ExpressionStatement') return undefined;
  const e = stmt.expression;
  if (e.type !== 'AssignmentExpression' || e.operator !== '=' || e.left.type !== 'Identifier' || e.left.name !== name) return undefined;
  return staticString(e.right, scope) !== undefined || e.right.type === 'NumericLiteral' ? e : undefined;
}

/**
 * Whether an earlier statement of the same function holds the name to fixed
 * values where it is used: a guard that leaves unless the value is one of
 * them (`if (!ALLOWED.includes(col)) throw …`, `if (x !== "asc" && x !==
 * "desc") return …`) or that resets it to a fixed value (`if (…) x = "asc"`).
 * The name may be assigned only before the guard, or by the guard itself.
 */
const ifStatementsOf = new WeakMap<Node[], number[]>();
/** Earlier `if` statements of one body examined for a guard. */
const MAX_GUARDS = 64;

function guardedBefore(path: NodePath, binding: Binding): boolean {
  const name = binding.identifier.name;
  const stop = binding.scope.path;
  for (let at: NodePath | null = path; at && at !== stop; at = at.parentPath) {
    if (!at.isStatement() || !Array.isArray(at.container) || at.listKey !== 'body' || typeof at.key !== 'number') continue;
    // The `if` statements of the body, found once per body: walking every
    // earlier statement of a long body at every use of a name was quadratic
    const siblings = at.container as Node[];
    let ifs = ifStatementsOf.get(siblings);
    if (!ifs) {
      ifs = [];
      for (let k = 0; k < siblings.length; k++) if (siblings[k]?.type === 'IfStatement') ifs.push(k);
      ifStatementsOf.set(siblings, ifs);
    }
    // the last `if` before this statement, then back (at most MAX_GUARDS of them)
    let lo = 0;
    let hi = ifs.length;
    while (lo < hi) {
      const mid = (lo + hi) >> 1;
      if (ifs[mid] < at.key) lo = mid + 1;
      else hi = mid;
    }
    for (let i = lo - 1; i >= 0 && i >= lo - MAX_GUARDS; i--) {
      const prev = siblings[ifs[i]];
      if (prev?.type !== 'IfStatement') continue;
      const test = prev.test;
      if (assignedNames(test).has(name) || !choiceChecked(test, false, at.scope).has(name)) continue;
      const reset = fixedReassignment(prev.consequent, name, at.scope);
      if (!reset && !alwaysExits(prev.consequent)) continue;
      const start = prev.start ?? 0;
      if (binding.constantViolations.every((v) => v.node === reset || (v.node.end ?? 0) <= start)) return true;
    }
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
  const test = path.node.test;
  // the checked value is one of the fixed choices only in the branch where the test says so
  const fixed = (branch: Node, checked: Set<string>): boolean =>
    staticString(branch, path.scope) !== undefined || branch.type === 'NumericLiteral'
    || (branch.type === 'Identifier' && checked.has(branch.name));
  // a name the test itself assigns (`ALLOWED.includes(c) && (c = o, true)`) holds what was assigned
  const assigned = assignedNames(test);
  const checked = (outcome: boolean): Set<string> => {
    const names = choiceChecked(test, outcome, path.scope);
    for (const n of assigned) names.delete(n);
    return names;
  };
  return fixed(path.node.consequent, checked(true)) && fixed(path.node.alternate, checked(false));
}

/** Names an expression assigns or updates (`x = …`, `x += …`, `x++`), however deep. */
function assignedNames(node: Node, depth = 0, into = new Set<string>()): Set<string> {
  if (depth > 32) return into;
  if (node.type === 'AssignmentExpression' && node.left.type === 'Identifier') into.add(node.left.name);
  if (node.type === 'UpdateExpression' && node.argument.type === 'Identifier') into.add(node.argument.name);
  // functions in the test run later, if ever: what they assign is not the test's
  if (node.type === 'ArrowFunctionExpression' || node.type === 'FunctionExpression') return into;
  for (const key of Object.keys(node) as Array<keyof Node>) {
    if (key === 'loc' || key === 'leadingComments' || key === 'trailingComments' || key === 'innerComments') continue;
    const value = node[key] as unknown;
    for (const child of Array.isArray(value) ? value : [value]) {
      if (child && typeof child === 'object' && typeof (child as Node).type === 'string') assignedNames(child as Node, depth + 1, into);
    }
  }
  return into;
}

/**
 * The names a test proves to be one of fixed values when it evaluates to
 * `outcome`: `ALLOWED.includes(x)` (true), `x !== "asc"` (false),
 * `!ALLOWED.includes(x)` (false). `A && B` true makes both hold, so every
 * operand's check counts (`ALLOWED.includes(o) && ALLOWED.includes(col)`);
 * `A || B` false makes both fail. `A && B` false and `A || B` true make one
 * hold: a name both operands check (`x !== "asc" && x !== "desc"`).
 */
function choiceChecked(test: Node, outcome: boolean, scope: Scope, depth = 0, into = new Set<string>()): Set<string> {
  if (depth > 8) return into;
  if (test.type === 'ParenthesizedExpression') return choiceChecked(test.expression, outcome, scope, depth + 1, into);
  if (test.type === 'UnaryExpression' && test.operator === '!') return choiceChecked(test.argument, !outcome, scope, depth + 1, into);
  if (test.type === 'LogicalExpression') {
    // `A && B` true: both true; `A || B` false: both false
    if ((test.operator === '&&' && outcome) || (test.operator === '||' && !outcome)) {
      choiceChecked(test.left, outcome, scope, depth + 1, into);
      choiceChecked(test.right, outcome, scope, depth + 1, into);
    } else if (test.operator === '&&' || test.operator === '||') {
      // `x !== "asc" && x !== "desc"` false, `x === "asc" || x === "desc"` true:
      // one operand holds, so a name every operand checks is fixed
      const left = choiceChecked(test.left, outcome, scope, depth + 1);
      const right = choiceChecked(test.right, outcome, scope, depth + 1);
      for (const n of left) if (right.has(n)) into.add(n);
    }
    return into;
  }
  const name = checkedName(test, outcome, scope);
  if (name !== undefined) into.add(name);
  return into;
}

/** The name one comparison or membership test proves fixed when it evaluates to `outcome`. */
function checkedName(test: Node, outcome: boolean, scope: Scope): string | undefined {
  if (test.type === 'CallExpression') {
    const callee = test.callee;
    const first = test.arguments[0];
    if (outcome && callee.type === 'MemberExpression' && callee.property.type === 'Identifier' && /^(?:includes|has)$/.test(callee.property.name)
      && first?.type === 'Identifier' && fixedList(callee.object, scope)) {
      return first.name;
    }
    return undefined;
  }
  if (test.type === 'BinaryExpression' && /^(?:===|==|!==|!=)$/.test(test.operator)) {
    // `x === "asc"` true, `x !== "asc"` false
    if (outcome === test.operator.startsWith('!')) return undefined;
    const { left, right } = test;
    if (left.type === 'Identifier' && staticString(right, scope) !== undefined) return left.name;
    if (right.type === 'Identifier' && left.type !== 'PrivateName' && staticString(left, scope) !== undefined) return right.name;
    return undefined;
  }
  if (outcome && test.type === 'BinaryExpression' && test.operator === 'in' && test.left.type === 'Identifier' && fixedList(test.right, scope)) {
    return test.left.name;
  }
  return undefined;
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
  // the program as a literal, or a constant holding one (`const shell = "/bin/sh"`)
  const programText = program ? staticString(program, args[0].scope) : undefined;
  const viaShell =
    (programText !== undefined && SHELLS.test(programText)) ||
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
