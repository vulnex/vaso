/**
 * External content → tool result tracing (MCP-007). Content a server fetched
 * over HTTP, or read from a file, and handed to the model as a tool result is
 * where indirect prompt injection enters: the model reads it as context, and
 * whoever controls that content can steer the model.
 *
 * JavaScript: a value derived from an HTTP call (`fetch`, axios, got, ky,
 * undici, superagent — through `.json()`/`.text()`/`.then()`, variables and
 * the return values of local functions) or a file read that reaches a
 * `{ type: 'text', text: … }` content block.
 *
 * Python: a tool function (`@mcp.tool()`, `@server.call_tool()`, …) that makes
 * an HTTP request (requests, httpx, aiohttp, urllib) or reads a file and
 * returns a value — itself or through a helper in the same module.
 *
 * How much the content can be trusted depends on where it comes from, so each
 * flow says: a URL the caller chooses (any page, attacker-written included), a
 * host where anyone can publish (Wikipedia, Reddit, forums), or a fixed API.
 */

import { createHash } from 'node:crypto';
import _traverse from '@babel/traverse';
import type { Binding, NodePath } from '@babel/traverse';
import type { Node } from '@babel/types';
import { parseJs, sourceChunks } from './js-parse.js';
import { FS_CALLS, FS_MODULE, bindingModule, isFsObject, localCallees } from './tool-input-taint.js';
import { blankStrings, callArgs, codeLines, mapStringLiterals, splitArgs, statements, topLevelParts } from './python-sinks.js';

const traverse = typeof _traverse === 'function' ? _traverse : (_traverse as { default: typeof _traverse }).default;

export interface ExternalContentFlow {
  line: number;
  snippet: string;
  via: 'http' | 'file';
  /** Host of the URL when it starts with a literal. */
  host?: string;
  /** The URL starts with a value the caller supplies (a handler/function parameter). */
  callerChosenUrl: boolean;
  /** The host is one where anyone can publish content. */
  openContentHost: boolean;
  /** The call the content comes from, e.g. `fetch`, `httpx.get`. */
  source: string;
}

/**
 * Hosts serving content anyone can write — pages, comments, posts, answers.
 * A fixed first-party API (a status page, a weather service) is not on it.
 */
const OPEN_CONTENT_HOSTS = [
  'wikipedia.org', 'wikimedia.org', 'wikidata.org', 'fandom.com',
  'reddit.com', 'redd.it',
  'news.ycombinator.com', 'hacker-news.firebaseio.com', 'hn.algolia.com',
  'stackoverflow.com', 'stackexchange.com',
  'twitter.com', 'x.com', 'nitter.net', 'mastodon.social', 'bsky.app', 'bsky.social',
  'youtube.com', 'medium.com', 'substack.com', 'quora.com', 'discord.com',
  'pastebin.com', 'gist.githubusercontent.com', 'raw.githubusercontent.com',
  'r.jina.ai',
];

export function isOpenContentHost(host: string): boolean {
  const h = host.toLowerCase().replace(/\.$/, '');
  return OPEN_CONTENT_HOSTS.some((d) => h === d || h.endsWith(`.${d}`));
}

function hostOf(url: string): string | undefined {
  return /^https?:\/\/([^/:?#\s]+)/i.exec(url)?.[1];
}

const HTTP_FUNCTIONS = new Set(['fetch', 'got', 'ky', 'request', 'superagent', 'needle', 'axios']);
const HTTP_CLIENTS = new Set(['axios', 'got', 'ky', 'undici', 'superagent', 'needle', 'request', 'client', 'http', 'httpClient']);
const HTTP_METHODS = new Set(['get', 'post', 'put', 'patch', 'request', 'fetch', 'head']);

/** Receiver names that are not necessarily HTTP clients. */
const GENERIC_CLIENTS = new Set(['client', 'request']);
const URL_NAME = /url|uri|endpoint|href|link|path|route/i;

/** An argument that looks like a URL: a literal/template starting with a scheme or `/`, or a URL-named value. */
function urlish(node: Node | undefined): boolean {
  if (!node) return false;
  if (node.type === 'StringLiteral') return /^(?:https?:\/\/|\/)/i.test(node.value);
  if (node.type === 'TemplateLiteral') {
    const first = node.quasis[0]?.value.cooked ?? '';
    return first ? /^(?:https?:\/\/|\/)/i.test(first) : urlish(node.expressions[0] as Node | undefined);
  }
  if (node.type === 'BinaryExpression') return urlish(node.left as Node);
  if (node.type === 'NewExpression') return node.callee.type === 'Identifier' && node.callee.name === 'URL';
  if (node.type === 'ObjectExpression') return node.properties.some((p) => p.type === 'ObjectProperty' && p.key.type === 'Identifier' && p.key.name === 'url');
  if (node.type === 'Identifier') return URL_NAME.test(node.name);
  if (node.type === 'MemberExpression') return node.property.type === 'Identifier' && URL_NAME.test(node.property.name);
  return false;
}

/** Filters a server runs content through before returning it. */
const SANITIZER = /sanitiz|escape|strip|purify|redact|clean|neutrali[sz]e|filter(?:Injection|Instructions|Prompt)/i;

function calleeName(callee: Node): string {
  if (callee.type === 'Identifier') return callee.name;
  if (callee.type === 'MemberExpression' && callee.property.type === 'Identifier') return callee.property.name;
  return '';
}

const MAX_DEPTH = 8;
const MAX_CACHED = 1_000;
const cache = new Map<string, ExternalContentFlow[]>();

export function findExternalContentFlows(code: string, language: 'javascript' | 'python' = 'javascript', filename = 'unknown'): ExternalContentFlow[] {
  const key = `${language}\0${filename}\0${createHash('sha1').update(code).digest('base64')}`;
  const cached = cache.get(key);
  if (cached) return cached.map((f) => ({ ...f }));
  const results = language === 'python'
    ? analyzePython(code)
    : sourceChunks(code).flatMap((chunk) =>
      analyzeJs(chunk.code).map((f) => ({ ...f, line: f.line + chunk.startLine - 1 })));
  if (cache.size >= MAX_CACHED) cache.delete(cache.keys().next().value!);
  cache.set(key, results);
  return results.map((f) => ({ ...f }));
}

// ── JavaScript ──────────────────────────────────────────────────────────

interface Origin {
  call: NodePath;
  via: 'http' | 'file';
  source: string;
}

function analyzeJs(code: string): ExternalContentFlow[] {
  const ast = parseJs(code);
  if (!ast) return [];
  let lines: string[] | undefined;
  const lineText = (line: number): string => (lines ??= code.split('\n'))[line - 1]?.trim() ?? '';
  const results: ExternalContentFlow[] = [];

  try {
    /** The content-source call a call expression is, if any. */
    const sourceCall = (path: NodePath): Origin | undefined => {
      if (!path.isCallExpression() && !path.isNewExpression()) return undefined;
      const callee = path.node.callee;
      if (callee.type === 'Identifier') {
        if (HTTP_FUNCTIONS.has(callee.name)) return { call: path, via: 'http', source: callee.name };
        const fsCall = FS_CALLS[callee.name];
        if (fsCall?.kind === 'file-read' && FS_MODULE.test(bindingModule(path.scope.getBinding(callee.name)) ?? '')) {
          return { call: path, via: 'file', source: callee.name };
        }
        return undefined;
      }
      if (callee.type === 'MemberExpression' && callee.property.type === 'Identifier') {
        const prop = callee.property.name;
        if (FS_CALLS[prop]?.kind === 'file-read' && isFsObject(path, callee.object)) {
          return { call: path, via: 'file', source: prop };
        }
        if (callee.object.type === 'Identifier' && HTTP_CLIENTS.has(callee.object.name) && HTTP_METHODS.has(prop)) {
          // `client.get(key)` is as often a cache/DB client (memcached, redis);
          // a generic receiver counts only when it is handed a URL.
          if (GENERIC_CLIENTS.has(callee.object.name) && !urlish(path.node.arguments[0] as Node | undefined)) return undefined;
          return { call: path, via: 'http', source: `${callee.object.name}.${prop}` };
        }
      }
      return undefined;
    };

    // Local functions whose return value carries fetched/read content.
    const sourceFunctions = new WeakMap<Node, Origin>();
    let memo = new Map<Binding, Origin | null>();

    const bindingOrigin = (binding: Binding, depth: number): Origin | undefined => {
      if (memo.has(binding)) return memo.get(binding) ?? undefined;
      memo.set(binding, null);
      let origin: Origin | undefined;
      if (depth < MAX_DEPTH && (binding.kind === 'const' || binding.kind === 'let' || binding.kind === 'var')) {
        const declarator = binding.path;
        if (declarator.isVariableDeclarator()) {
          const init = declarator.get('init');
          if (init.node) origin = expressionOrigin(init as NodePath, depth + 1);
        }
        for (const violation of binding.constantViolations) {
          if (origin) break;
          if (violation.isAssignmentExpression()) origin = expressionOrigin(violation.get('right'), depth + 1);
        }
      }
      memo.set(binding, origin ?? null);
      return origin;
    };

    /**
     * Values that aren't the content even when built from it: a filter's
     * output (`sanitize(raw)`, `stripInstructions(t)`), key lists and sizes
     * (`Object.keys(docs)`, `items.length`).
     */
    const blocked = (p: NodePath): boolean => {
      if (p.isCallExpression()) {
        const callee = p.node.callee;
        if (SANITIZER.test(calleeName(callee))) return true;
        return callee.type === 'MemberExpression' && callee.object.type === 'Identifier' && callee.object.name === 'Object' &&
          callee.property.type === 'Identifier' && callee.property.name === 'keys';
      }
      return p.isMemberExpression() && p.node.property.type === 'Identifier' && p.node.property.name === 'length';
    };

    const expressionOrigin = (path: NodePath, depth: number): Origin | undefined => {
      const visit = (p: NodePath): Origin | undefined => {
        const direct = sourceCall(p);
        if (direct) return direct;
        if (p.isCallExpression()) {
          for (const fn of localCallees(p)) {
            const hit = sourceFunctions.get(fn);
            if (hit) return hit;
          }
        }
        if (p.isIdentifier() && p.isReferencedIdentifier()) {
          const binding = p.scope.getBinding(p.node.name);
          if (binding) return bindingOrigin(binding, depth);
        }
        return undefined;
      };
      if (blocked(path)) return undefined;
      let found = visit(path);
      if (found) return found;
      path.traverse({
        enter(p) {
          if (found) return p.stop();
          // A callback's body (`.then(r => r.json())`) works on the value
          // already traced; other nested functions don't flow into it.
          if (p.isFunction() || blocked(p)) return p.skip();
          found = visit(p);
        },
      });
      return found;
    };

    const returnsOf = (fn: NodePath): NodePath[] => {
      const out: NodePath[] = [];
      const body = fn.get('body') as NodePath;
      if (!Array.isArray(body) && body.node && !body.isBlockStatement()) return [body];
      fn.traverse({
        ReturnStatement(r) {
          if (r.getFunctionParent() === fn) {
            const arg = r.get('argument') as NodePath;
            if (arg.node) out.push(arg);
          }
        },
      });
      return out;
    };

    // Fixpoint over helper → helper chains.
    for (let round = 0; round < 4; round++) {
      let changed = false;
      memo = new Map();
      traverse(ast, {
        Function(fn) {
          if (sourceFunctions.has(fn.node)) return;
          for (const ret of returnsOf(fn)) {
            const origin = expressionOrigin(ret, 0);
            if (origin) {
              sourceFunctions.set(fn.node, origin);
              changed = true;
              return;
            }
          }
        },
      });
      if (!changed) break;
    }
    memo = new Map();

    traverse(ast, {
      ObjectProperty(path) {
        const { key } = path.node;
        const keyName = key.type === 'Identifier' ? key.name : key.type === 'StringLiteral' ? key.value : undefined;
        if (keyName !== 'text') return;
        const obj = path.parentPath;
        if (!obj?.isObjectExpression()) return;
        const isTextBlock = obj.node.properties.some((p) =>
          p.type === 'ObjectProperty' &&
          ((p.key.type === 'Identifier' && p.key.name === 'type') || (p.key.type === 'StringLiteral' && p.key.value === 'type')) &&
          p.value.type === 'StringLiteral' && p.value.value === 'text');
        if (!isTextBlock) return;
        const value = path.get('value') as NodePath;
        const origin = expressionOrigin(value, 0);
        if (!origin) return;
        const line = path.node.loc?.start.line ?? 0;
        results.push({ line, snippet: lineText(line).slice(0, 120), ...classify(origin) });
      },
    });
  } catch {
    // Pathological ASTs (errorRecovery output) — report what was found so far.
  }
  return results;
}

/** Where the content behind `origin` comes from: its URL's host and who picks it. */
function classify(origin: Origin): Omit<ExternalContentFlow, 'line' | 'snippet'> {
  if (origin.via === 'file') return { via: 'file', callerChosenUrl: false, openContentHost: false, source: origin.source };
  const args = (origin.call.get('arguments') as NodePath[]) ?? [];
  // axios.get(url) / fetch(url) / got(url); axios({ url })
  let urlArg: NodePath | undefined = args[0];
  if (urlArg?.isObjectExpression()) {
    const prop = (urlArg.get('properties') as NodePath[]).find((p) =>
      p.isObjectProperty() && p.node.key.type === 'Identifier' && p.node.key.name === 'url');
    urlArg = prop ? (prop.get('value') as NodePath) : undefined;
  }
  const start = urlArg ? leftmost(urlArg, 0) : undefined;
  const host = start?.literal ? hostOf(start.literal) : undefined;
  return {
    via: 'http',
    source: origin.source,
    callerChosenUrl: Boolean(start?.param),
    openContentHost: host ? isOpenContentHost(host) : false,
    ...(host ? { host } : {}),
  };
}

/**
 * How far a URL is followed back through variables, wrapper functions and
 * their call sites: real servers wrap fetch twice or more
 * (`makeApiRequest` → `proxyAwareFetch` → `fetch`), each hop a few steps.
 */
const URL_MAX_DEPTH = 16;

/** The first piece of a URL expression: a literal prefix, or the parameter it starts with. */
function leftmost(path: NodePath, depth: number): { literal?: string; param?: string } | undefined {
  if (depth > URL_MAX_DEPTH || !path.node) return undefined;
  if (path.isStringLiteral()) return { literal: path.node.value };
  if (path.isTemplateLiteral()) {
    const first = path.node.quasis[0]?.value.cooked ?? '';
    if (first) return { literal: first };
    const expr = (path.get('expressions') as NodePath[])[0];
    return expr ? leftmost(expr, depth + 1) : undefined;
  }
  if (path.isBinaryExpression() && path.node.operator === '+') return leftmost(path.get('left') as NodePath, depth + 1);
  if (path.isAwaitExpression()) return leftmost(path.get('argument') as NodePath, depth + 1);
  // The same URL as text: `url.toString()`, `url.href`, `String(url)`
  if (path.isCallExpression()) {
    const callee = path.get('callee') as NodePath;
    const args = path.get('arguments') as NodePath[];
    if (callee.isMemberExpression() && !callee.node.computed && callee.node.property.type === 'Identifier'
      && callee.node.property.name === 'toString' && args.length === 0) return leftmost(callee.get('object') as NodePath, depth + 1);
    if (callee.isIdentifier() && callee.node.name === 'String' && args.length === 1) return leftmost(args[0], depth + 1);
    return undefined;
  }
  if (path.isMemberExpression() && !path.node.computed && path.node.property.type === 'Identifier' && path.node.property.name === 'href') {
    return leftmost(path.get('object') as NodePath, depth + 1);
  }
  if (path.isNewExpression() && path.node.callee.type === 'Identifier' && path.node.callee.name === 'URL') {
    const [input, base] = path.get('arguments') as NodePath[];
    return base?.node ? leftmost(base, depth + 1) : input ? leftmost(input, depth + 1) : undefined;
  }
  if (path.isMemberExpression() || path.isOptionalMemberExpression()) {
    // `args.url`, `request.params.arguments.url`: the URL is the caller's.
    let object: NodePath = path.get('object') as NodePath;
    while (object.isMemberExpression() || object.isOptionalMemberExpression()) object = object.get('object') as NodePath;
    return object.isIdentifier() ? fromIdentifier(object, depth) : undefined;
  }
  if (path.isIdentifier()) return fromIdentifier(path, depth);
  return undefined;
}

function fromIdentifier(path: NodePath, depth: number): { literal?: string; param?: string } | undefined {
  if (!path.isIdentifier()) return undefined;
  const binding = path.scope.getBinding(path.node.name);
  if (!binding) return undefined;
  if (binding.kind === 'param') return fromCallSites(binding, depth) ?? { param: path.node.name };
  const declarator = binding.path;
  if (declarator.isVariableDeclarator()) {
    // `const { url } = args` — destructured from a parameter.
    if (declarator.node.id.type === 'ObjectPattern') {
      const init = declarator.get('init') as NodePath;
      return init.node ? leftmost(init, depth + 1) : undefined;
    }
    if (binding.constant) {
      const init = declarator.get('init') as NodePath;
      return init.node ? leftmost(init, depth + 1) : undefined;
    }
  }
  return undefined;
}

/**
 * A parameter of a local helper (`fetchWithTimeout(url, opts)`) is only as
 * caller-chosen as what its call sites pass: `fetchWithTimeout(`${BASE}/status`)`
 * fetches a fixed API. Undefined — the parameter counts as the caller's —
 * when the function is a handler or passed around as a value (a tool or
 * request handler: `server.tool(…, async ({ url }) => …)`), or has no calls.
 */
function fromCallSites(binding: Binding, depth: number): { literal?: string; param?: string } | undefined {
  if (depth > URL_MAX_DEPTH) return undefined;
  const fn = binding.scope.path;
  if (!fn.isFunction()) return undefined;
  const index = fn.node.params.findIndex((p) => p === binding.path.node || (p.type === 'AssignmentPattern' && p.left === binding.path.node));
  if (index < 0) return undefined;
  // The function's own name: a declaration, or `const f = (…) => …`
  const id = fn.isFunctionDeclaration() ? fn.node.id
    : fn.parentPath?.isVariableDeclarator() && fn.parentPath.node.id.type === 'Identifier' ? fn.parentPath.node.id : undefined;
  const named = id ? (fn.isFunctionDeclaration() ? fn.parentPath?.scope : fn.scope.parent)?.getBinding(id.name) : undefined;
  // `export function f`: other modules may call it too, but their calls
  // don't feed this module's tool results — the calls here do
  const refs = named?.referencePaths.filter((r) => !r.isExportDeclaration() && !r.parentPath?.isExportSpecifier()) ?? [];
  if (refs.length === 0) return undefined;
  let literal: string | undefined;
  for (const ref of refs) {
    const call = ref.parentPath;
    if (!call?.isCallExpression() || call.node.callee !== ref.node) return undefined; // used as a value
    const arg = (call.get('arguments') as NodePath[])[index];
    const start = arg?.node ? leftmost(arg, depth + 1) : undefined;
    if (start?.param) return { param: start.param };
    const host = start?.literal ? hostOf(start.literal) : undefined;
    if (start?.literal && (literal === undefined || (host && isOpenContentHost(host)))) literal = start.literal;
  }
  return literal !== undefined ? { literal } : {};
}

// ── Python ─────────────────────────────────────────────────────────────

const PY_TOOL_DECORATOR = /^\s*@\s*[\w.]+\.(?:tool|call_tool)\s*\(/;
const PY_HTTP_CALL = /\b(?:requests|httpx|client|session|http|aiohttp|urllib\.request)\s*\.\s*(?:get|post|request|stream|urlopen)\s*\(|\burlopen\s*\(/;
/** An HTTP client or session object created here: `httpx.AsyncClient(`, `requests.Session(`, curl_cffi `AsyncSession(`. */
const PY_CLIENT_CTOR = /\b(?:AsyncClient|Client|Session|AsyncSession|ClientSession)\s*\(/;
/** `return` of a value, not just a literal message (`return "Not found."`). */
const PY_RETURNS_VALUE = (text: string): boolean =>
  /^\s*return\s+\S/.test(text) && !/^\s*return\s+(?:f?["'][^"'{]*["']|None|True|False|\d+)\s*$/.test(text);
const PY_MAX_DEPTH = 4;
/** Calls whose result carries their arguments' text (string building, parsing, result wrappers). */
const PY_PASSTHROUGH = /^(?:str|repr|format|join|replace|strip|lstrip|rstrip|lower|upper|split|splitlines|list|tuple|dict|sorted|reversed|next|iter|values|items|get|pop|encode|decode|copy|loads|dumps|json\.loads|json\.dumps|BeautifulSoup|markdownify|html2text|handle|unescape|dedent|TextContent|truncate|cast)$/;

/** Where a URL expression starts: a literal prefix, or a parameter (by position) of the function it is in. */
interface PyStart {
  literal?: string;
  param?: number;
}

interface PyFn {
  name: string;
  /** Parameters by position, `self`/`cls` dropped. */
  params: string[];
  /** Statement range: the `def` statement and its body. */
  def: number;
  end: number;
  module: number;
  cls?: string;
  tool: boolean;
}

interface PyFlow {
  line: number;
  snippet: string;
  via: 'http' | 'file';
  /** The HTTP library or file call (`httpx`, `open`). */
  base: string;
  /** Helpers the content came through, outermost first. */
  through: string[];
  start: PyStart;
}

/**
 * Python tool functions (`@mcp.tool()`, `@server.call_tool()`) that return a
 * value after fetching a URL or reading a file — directly, or through a helper
 * in the same module: a function (`fetch_page(url)`), a method of a class
 * instantiated at module level (`fetcher.fetch_and_parse(url)`), or a method
 * on `self`. Line-based, like the rest of the Python analysis: statements are
 * merged across brackets, assignments followed in order, and a helper's URL
 * parameter is mapped to what each call site passes, so a tool's URL counts
 * as caller-chosen only when the tool's own input reaches the request.
 */
function analyzePython(code: string): ExternalContentFlow[] {
  const rawLines = code.split('\n');
  const stmts = statements(codeLines(code));
  const blanked = stmts.map((s) => blankStrings(s.text));
  const indentOf = (i: number): number => stmts[i].text.search(/\S/);

  // Modules of a joined multi-file source (`// === pkg/server.py ===`)
  const moduleOf: number[] = [];
  let module = 0;
  for (let i = 0; i < stmts.length; i++) {
    if (/^\s*\/\/ === .* ===\s*$/.test(stmts[i].text)) module++;
    moduleOf.push(module);
  }
  const bodyEnd = (i: number): number => {
    const indent = indentOf(i);
    let end = i + 1;
    while (end < stmts.length && moduleOf[end] === moduleOf[i] && indentOf(end) > indent) end++;
    return end;
  };

  // Classes, their string attributes; module string constants; module-level instances
  const classes = new Map<string, { attrs: Map<string, string> }>(); // `${module}:${name}`
  const constants = new Map<string, string>(); // `${module}:${name}` → literal
  const instances = new Map<string, string>(); // `${module}:${name}` → class name
  const stringValue = (expr: string): string | undefined => /^\s*[rRbBuU]{0,2}(["'])([^"']*)\1\s*$/.exec(expr)?.[2];
  for (let i = 0; i < stmts.length; i++) {
    const cls = /^(\s*)class\s+(\w+)/.exec(stmts[i].text);
    if (!cls) continue;
    const attrs = new Map<string, string>();
    const end = bodyEnd(i);
    const inner = i + 1 < end ? indentOf(i + 1) : -1;
    for (let j = i + 1; j < end; j++) {
      if (indentOf(j) !== inner) continue;
      const a = /^\s*([A-Za-z_]\w*)\s*(?::[^=]+)?=(?!=)\s*(.*)$/.exec(stmts[j].text);
      const v = a ? stringValue(a[2]) : undefined;
      if (a && v !== undefined) attrs.set(a[1], v);
    }
    classes.set(`${moduleOf[i]}:${cls[2]}`, { attrs });
  }
  for (let i = 0; i < stmts.length; i++) {
    if (indentOf(i) !== 0) continue;
    const a = /^([A-Za-z_]\w*)\s*(?::[^=]+)?=(?!=)\s*(.*)$/.exec(stmts[i].text);
    if (!a) continue;
    const v = stringValue(a[2]);
    if (v !== undefined) constants.set(`${moduleOf[i]}:${a[1]}`, v);
    const ctor = /^([A-Za-z_]\w*)\s*\(/.exec(a[2].trim())?.[1];
    if (ctor && classes.has(`${moduleOf[i]}:${ctor}`)) instances.set(`${moduleOf[i]}:${a[1]}`, ctor);
  }

  // Functions and methods
  const fns: PyFn[] = [];
  for (let i = 0; i < stmts.length; i++) {
    const def = /^(\s*)(?:async\s+)?def\s+(\w+)\s*\(/.exec(stmts[i].text);
    if (!def) continue;
    const indent = def[1].length;
    let params = topLevelParts(callArgs(stmts[i].text, def[0].length - 1))
      .map((p) => /^\s*\**([A-Za-z_]\w*)/.exec(p)?.[1])
      .filter((p): p is string => !!p);
    let cls: string | undefined;
    for (let j = i - 1; j >= 0 && moduleOf[j] === moduleOf[i]; j--) {
      if (stmts[j].text.trim() === '' || indentOf(j) >= indent) continue;
      cls = /^\s*class\s+(\w+)/.exec(stmts[j].text)?.[1];
      break;
    }
    if (cls && (params[0] === 'self' || params[0] === 'cls')) params = params.slice(1);
    let tool = false;
    for (let d = i - 1; d >= 0 && /^\s*@/.test(stmts[d].text); d--) if (PY_TOOL_DECORATOR.test(stmts[d].text)) tool = true;
    fns.push({ name: def[2], params, def: i, end: bodyEnd(i), module: moduleOf[i], ...(cls ? { cls } : {}), tool });
  }
  const functionNamed = (module: number, name: string, cls?: string): PyFn | undefined =>
    fns.find((f) => f.module === module && f.name === name && f.cls === cls);

  /** Where an expression in `fn` starts, given the aliases assigned so far. */
  const startOf = (raw: string, fn: PyFn, aliases: Map<string, PyStart>, depth = 0): PyStart | undefined => {
    if (depth > 6) return undefined;
    let e = raw.trim().replace(/^await\s+/, '');
    if (!e) return undefined;
    const quoted = /^([rRbBuUfF]{0,2})(["'])/.exec(e);
    if (quoted) {
      const body = e.slice(quoted[0].length);
      const close = body.indexOf(quoted[2]);
      const text = close < 0 ? body : body.slice(0, close);
      if (/f/i.test(quoted[1])) {
        const brace = text.indexOf('{');
        if (brace === 0) return startOf(/^\{([^}]*)\}/.exec(text)?.[1] ?? '', fn, aliases, depth + 1);
        return { literal: brace < 0 ? text : text.slice(0, brace) };
      }
      return { literal: text };
    }
    // `a + b`, `a % b`: the left operand starts it
    const clean = mapStringLiterals(e, (m) => '_'.repeat(m.length));
    let level = 0;
    for (let i = 0; i < clean.length; i++) {
      const c = clean[i];
      if (c === '(' || c === '[' || c === '{') level++;
      else if (c === ')' || c === ']' || c === '}') level--;
      else if (level === 0 && (c === '+' || c === '%') && i > 0) return startOf(e.slice(0, i), fn, aliases, depth + 1);
    }
    if (e.startsWith('(') && e.endsWith(')')) return startOf(e.slice(1, -1), fn, aliases, depth + 1);
    const wrapped = /^(?:str|httpx\.URL|URL|urllib\.parse\.quote|quote)\s*\(/.exec(e);
    if (wrapped) return startOf(topLevelParts(callArgs(e, wrapped[0].length - 1))[0] ?? '', fn, aliases, depth + 1);
    const ref = /^([A-Za-z_]\w*)(?:\s*\.\s*([A-Za-z_]\w*))?/.exec(e);
    if (!ref) return undefined;
    const [, base, attr] = ref;
    if ((base === 'self' || base === 'cls') && attr && fn.cls) {
      const v = classes.get(`${fn.module}:${fn.cls}`)?.attrs.get(attr);
      return v !== undefined ? { literal: v } : undefined;
    }
    if (aliases.has(base)) return aliases.get(base);
    const index = fn.params.indexOf(base);
    if (index >= 0) return { param: index };
    const constant = constants.get(`${fn.module}:${base}`);
    if (constant !== undefined && !attr) return { literal: constant };
    if (attr) {
      const v = classes.get(`${fn.module}:${base}`)?.attrs.get(attr);
      if (v !== undefined) return { literal: v };
    }
    return undefined;
  };

  /** The argument a call passes for a callee's parameter `index`. */
  const argumentFor = (args: string, callee: PyFn, index: number): string | undefined => {
    const { positional, keywords } = splitArgs(args);
    return keywords.get(callee.params[index]) ?? positional[index];
  };

  /** Rank of a flow's URL: a parameter (may be the caller's) > an open-content host > anything else. */
  const rank = (f: PyFlow): number => {
    if (f.start.param !== undefined) return 3;
    const host = f.start.literal ? hostOf(f.start.literal) : undefined;
    return host && isOpenContentHost(host) ? 2 : 1;
  };

  /** The helper in `fn`'s module a call `owner.name(…)` / `name(…)` reaches: a function, a `self` method, a module-level instance's method. */
  const calleeOf = (fn: PyFn, owner: string | undefined, name: string): PyFn | undefined => {
    if (!owner) return functionNamed(fn.module, name);
    if ((owner === 'self' || owner === 'cls') && fn.cls) return functionNamed(fn.module, name, fn.cls);
    const cls = instances.get(`${fn.module}:${owner}`) ?? (classes.has(`${fn.module}:${owner}`) ? owner : undefined);
    return cls ? functionNamed(fn.module, name, cls) : undefined;
  };

  /**
   * `text` as data: f-string interpolations kept as `(a, b)`, other string
   * contents blanked, and each call reduced to what flows out of it — the
   * receiver of a method (`resp.json()`, `soup.select(…)`), plus the arguments
   * of calls that pass them through (`json.dumps(x)`, `str(x)`, `TextContent(…)`,
   * a helper in this module). Any other call returns its own value
   * (`api.post(url, files=data)` uploads `data`, it doesn't return it).
   */
  const dataView = (text: string, fn: PyFn): string => {
    let out = text.replace(/\b[rR]?[fF][rR]?("""|'''|"|')((?:\\.|(?!\1)[\s\S])*?)\1/g, (_m, _q: string, body: string) =>
      ` (${[...body.matchAll(/\{([^{}]*)\}/g)].map((m) => m[1].replace(/![rsa]$|:[^:]*$/, '')).join(', ')}) `);
    out = blankStrings(out);
    for (let guard = 0; guard < 64; guard++) {
      const m = /([A-Za-z_][\w.]*)\s*\(/.exec(out);
      if (!m) break;
      const open = m.index + m[0].length - 1;
      const args = callArgs(out, open);
      const dot = m[1].lastIndexOf('.');
      const name = dot === -1 ? m[1] : m[1].slice(dot + 1);
      const receiver = dot === -1 ? '' : m[1].slice(0, dot);
      // Helpers and classes of this module build their result from their arguments
      const local = (receiver === '' || /^[A-Za-z_]\w*$/.test(receiver)) &&
        (calleeOf(fn, receiver || undefined, name) !== undefined || (receiver === '' && classes.has(`${fn.module}:${name}`)));
      const keep = PY_PASSTHROUGH.test(m[1]) || PY_PASSTHROUGH.test(name) || local;
      out = out.slice(0, m.index) + ` ${receiver} ${keep ? args : ''} ` + out.slice(open + args.length + 2);
    }
    return out;
  };
  // A response's status is not its content: `f"Status: {r.status_code}"`
  // returns a number the server chose nothing about, not fetched text
  const STATUS_ONLY = /(?<![\w.])[A-Za-z_]\w*\s*\.\s*(?:status_code|status|ok|is_success|is_error|is_redirect|elapsed|encoding)\b(?!\s*[.([])/g;
  const mentionsAny = (text: string, names: Set<string>, fn: PyFn): boolean =>
    [...dataView(text, fn).replace(STATUS_ONLY, ' 0 ').matchAll(/(?<![\w.])[A-Za-z_]\w*/g)].some((m) => names.has(m[0]));

  /**
   * Whether the value of statement `i` — with the source call written as
   * `__src__` in `marked` — reaches a `return` of `fn`: through assignments,
   * `for x in …`, `with … as x`, `x.append(…)`, in two passes for loops.
   */
  const SRC = '__src__';
  const reachesReturn = (fn: PyFn, i: number, marked: string): boolean => {
    const tainted = new Set<string>([SRC]);
    const step = (text: string): boolean => {
      const ret = /^\s*return\s+([\s\S]+)$/.exec(text);
      if (ret) return PY_RETURNS_VALUE(text) && mentionsAny(ret[1], tainted, fn);
      const loop = /^\s*(?:async\s+)?for\s+([\w\s,()]+?)\s+in\s+([\s\S]+?):?\s*$/.exec(text);
      if (loop) {
        if (mentionsAny(loop[2], tainted, fn)) for (const n of loop[1].match(/[A-Za-z_]\w*/g) ?? []) tainted.add(n);
        return false;
      }
      const withAs = /^\s*(?:async\s+)?with\s+([\s\S]+):\s*$/.exec(text);
      if (withAs) {
        for (const part of topLevelParts(withAs[1])) {
          const as = /^([\s\S]+?)\s+as\s+([A-Za-z_]\w*)\s*$/.exec(part.trim());
          if (as && mentionsAny(as[1], tainted, fn)) tainted.add(as[2]);
        }
        return false;
      }
      const assign = /^\s*([A-Za-z_][\w\s,()]*?)(?:\[[^\]]*\])?\s*(?::[^=]+)?(?:[+|]?=)(?!=)\s*([\s\S]*)$/.exec(text);
      if (assign) {
        if (mentionsAny(assign[2], tainted, fn)) for (const n of assign[1].match(/[A-Za-z_]\w*/g) ?? []) tainted.add(n);
        return false;
      }
      const grow = /^\s*([A-Za-z_]\w*)\s*\.\s*(?:append|extend|add|update|insert|write)\s*\(([\s\S]*)\)\s*$/.exec(text);
      if (grow && mentionsAny(grow[2], tainted, fn)) tainted.add(grow[1]);
      return false;
    };
    if (step(marked)) return true;
    for (let pass = 0; pass < 2; pass++) {
      for (let j = pass === 0 ? i + 1 : fn.def + 1; j < fn.end; j++) {
        if (j === i) continue;
        if (step(stmts[j].text)) return true;
      }
    }
    return false;
  };
  /** Statement `i` with the call spanning [from, open…close paren] replaced by the source marker. */
  const markCall = (i: number, from: number, open: number): string => {
    const text = stmts[i].text;
    const args = callArgs(text, open);
    return `${text.slice(0, from)} ${SRC} ${text.slice(Math.min(text.length, open + args.length + 2))}`;
  };

  const memo = new Map<PyFn, PyFlow | null>();
  const flowOf = (fn: PyFn, depth: number): PyFlow | undefined => {
    if (memo.has(fn)) return memo.get(fn) ?? undefined;
    if (depth > PY_MAX_DEPTH) return undefined;
    memo.set(fn, null); // in progress: recursion finds nothing
    let best: PyFlow | undefined;
    const aliases = new Map<string, PyStart>();
    const fileHandles = new Set<string>();
    const consider = (flow: PyFlow, i: number, from: number, open: number) => {
      if (best && rank(flow) <= rank(best)) return;
      if (reachesReturn(fn, i, markCall(i, from, open))) best = flow;
    };
    const firstLine = (i: number): string => rawLines[stmts[i].line - 1]?.trim() ?? '';

    for (let i = fn.def + 1; i < fn.end; i++) {
      const text = stmts[i].text;
      const code = blanked[i];

      // The request, and the URL it is handed
      const http = PY_HTTP_CALL.exec(code);
      if (http) {
        const open = http.index + http[0].length - 1;
        const { positional, keywords } = splitArgs(callArgs(text, open));
        const method = /(\w+)\s*\($/.exec(http[0])?.[1];
        const urlExpr = keywords.get('url') ?? ((method === 'request' || method === 'stream') && positional.length > 1 ? positional[1] : positional[0]);
        const start = urlExpr ? startOf(urlExpr, fn, aliases) : undefined;
        const lastName = /^\s*(?:await\s+)?([A-Za-z_][\w.]*)/.exec(urlExpr ?? '')?.[1]?.split('.').pop();
        // `client.get(key)` on a memcached/redis client is a cache read; a
        // generic receiver counts when it is handed a URL, or was made as an
        // HTTP client in this function or at module level
        const receiver = /\b(client|session)\s*\.\s*get\s*\($/.exec(http[0])?.[1];
        const urlLike = start?.literal !== undefined ? /^(?:https?:\/\/|\/)/i.test(start.literal)
          : Boolean((lastName && URL_NAME.test(lastName)) || (start?.param !== undefined && URL_NAME.test(fn.params[start.param])));
        const made = receiver ? new RegExp(String.raw`${PY_CLIENT_CTOR.source}.*\bas\s+${receiver}\b|\b${receiver}\s*=\s*(?:await\s+)?[\w.]*?${PY_CLIENT_CTOR.source}`) : undefined;
        // `self.session.get(…)`: the session may be made in another method of
        // the class (`__init__: self.session = requests.Session()`)
        const onSelf = receiver !== undefined && fn.cls !== undefined && /\bself\s*\.\s*$/.test(code.slice(0, http.index));
        const inClass = (j: number): boolean => onSelf && fns.some((f) => f.cls === fn.cls && f.module === fn.module && j > f.def && j < f.end);
        const madeHere = made !== undefined && blanked.some((b, j) =>
          ((j > fn.def && j < fn.end) || (indentOf(j) === 0 && moduleOf[j] === fn.module) || inClass(j)) && made.test(b));
        if (!receiver || urlLike || madeHere) {
          consider({
            line: stmts[i].line, snippet: firstLine(i), via: 'http', through: [],
            base: /\b(requests|httpx|aiohttp|urllib|client|session)\b/.exec(http[0])?.[1] ?? 'http',
            start: start ?? {},
          }, i, http.index, open);
        }
      }

      // A file read: `open(p).read()`, `path.read_text()`, `with open(p) as f:` … `f.read()`
      const handle = /^\s*(?:async\s+)?with\s+open\s*\([^\n]*?\bas\s+([A-Za-z_]\w*)\s*:/.exec(code);
      if (handle && !/["'][wax]b?\+?["']/.test(text)) fileHandles.add(handle[1]);
      const reads = [
        /(?<![\w.])open\s*\([^()]*\)\s*\.\s*read(?:lines)?\s*\(/,
        /\.\s*read_(?:text|bytes)\s*\(/,
        ...[...fileHandles].map((h) => new RegExp(String.raw`(?<![\w.])${h}\s*\.\s*read(?:lines)?\s*\(`)),
      ];
      for (const re of reads) {
        const m = re.exec(code);
        if (!m || /["'][wax]b?\+?["']/.test(text.slice(m.index, m.index + m[0].length))) continue;
        const open = m.index + m[0].length - 1;
        consider({ line: stmts[i].line, snippet: firstLine(i), via: 'file', through: [], base: /read_(?:text|bytes)/.exec(m[0])?.[0] ?? 'open', start: {} }, i, m.index, open);
        break;
      }

      // Helpers in this module: `fetch(url)`, `self._fetch(url)`, `fetcher.fetch_and_parse(url)`
      for (const call of code.matchAll(/(?<![\w.])(?:([A-Za-z_]\w*)\s*\.\s*)?([A-Za-z_]\w*)\s*\(/g)) {
        const callee = calleeOf(fn, call[1], call[2]);
        if (!callee || callee === fn) continue;
        const inner = flowOf(callee, depth + 1);
        if (!inner) continue;
        const open = (call.index ?? 0) + call[0].length - 1;
        let start: PyStart = inner.start.literal !== undefined ? { literal: inner.start.literal } : {};
        if (inner.start.param !== undefined) {
          const arg = argumentFor(callArgs(text, open), callee, inner.start.param);
          start = (arg ? startOf(arg, fn, aliases) : undefined) ?? {};
        }
        consider({ line: stmts[i].line, snippet: firstLine(i), via: inner.via, base: inner.base, through: [callee.name, ...inner.through], start }, i, call.index ?? 0, open);
      }

      // Assignments, in order: `current = url`, `endpoint = f"{BASE}/x"`
      const assign = /^\s*([A-Za-z_]\w*)\s*(?::[^=]+)?=(?!=)\s*([\s\S]*)$/.exec(text);
      if (assign && fn.params.indexOf(assign[1]) < 0) {
        const s = startOf(assign[2], fn, aliases);
        if (s) aliases.set(assign[1], s);
        else aliases.delete(assign[1]);
      }
    }
    memo.set(fn, best ?? null);
    return best;
  };

  const results: ExternalContentFlow[] = [];
  for (const fn of fns) {
    if (!fn.tool) continue;
    const flow = flowOf(fn, 0);
    if (!flow) continue;
    const host = flow.via === 'http' && flow.start.literal ? hostOf(flow.start.literal) : undefined;
    const source = flow.through.length > 0 ? `${flow.base} via ${flow.through[0]}()` : flow.base;
    results.push({
      line: flow.line,
      snippet: flow.snippet.slice(0, 120),
      via: flow.via,
      source,
      callerChosenUrl: flow.via === 'http' && flow.start.param !== undefined,
      openContentHost: host ? isOpenContentHost(host) : false,
      ...(host ? { host } : {}),
    });
  }
  return results;
}
