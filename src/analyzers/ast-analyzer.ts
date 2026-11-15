import { createHash } from 'node:crypto';
import _traverse from '@babel/traverse';
import type { Node } from '@babel/types';
import type { Binding, NodePath } from '@babel/traverse';
import { cutLine } from './finding-snippet.js';
import { mayBeJavaScript, parseLenientReport, recordedEvasion, sourceChunks, type JsAst } from './js-parse.js';
import { bindingModule, memberName, sinkCallee } from './tool-input-taint.js';
import { analyzeFlows, type SourcePath, type Taint } from './js-flow.js';
import { credentialEnvName, onVendorHost, ownedCredential, signingSecret, staticOrigin, vendorApiDomains, vendorUrlSlot } from './vendor-domains.js';

// Handle ESM/CJS interop
const traverse = typeof _traverse === 'function' ? _traverse : (_traverse as { default: typeof _traverse }).default;

export interface DataFlowResult {
  /**
   * module-call / param-sink: a value read from a file or the environment
   * passed to a helper module of the skill, and a helper module's exported
   * parameter that reaches a send — joined across the skill's files by SKL-001.
   */
  type: 'source-to-sink' | 'eval-exec' | 'suspicious-network' | 'fs-access' | 'module-call' | 'param-sink';
  source?: string;
  /** source-to-sink: what the source variable holds — file contents or environment values. */
  sourceKind?: 'file' | 'env';
  sink?: string;
  /** source-to-sink: the receiver of a member-call sink (`axios` in `axios.post`, `res` in `res.send`). */
  sinkObject?: string;
  /** source-to-sink: the sink is `send` on a client socket the code opened (`new WebSocket(url)`). */
  socketClient?: boolean;
  /** source-to-sink: the source is the whole environment (`process.env`, or a variable holding it). */
  wholeEnv?: boolean;
  /**
   * source-to-sink (file): where the file read lives, when its path could be
   * worked out — a credential store, outside the skill and workspace, the
   * skill's own file, a workspace file, or chosen at runtime. Absent: unknown
   * (Python and line-scan flows), judged as before.
   */
  sourcePath?: SourcePath;
  /** source-to-sink (file): the path as resolved (`~/.ssh/id_rsa`). */
  resolvedPath?: string;
  /** source-to-sink: found by following the value (await, callbacks, transforms, helpers), not by name. */
  derived?: boolean;
  /** source-to-sink: the data leaves in a DNS query name. */
  dns?: boolean;
  /** module-call / param-sink: the relative module (`./lib/upload`), export and argument position. */
  module?: string;
  exportName?: string;
  argIndex?: number;
  /**
   * eval-exec: the call's static command/code text — string and template
   * parts, `${…}` for interpolations; absent when the argument is computed.
   */
  command?: string;
  /** eval-exec: the argument is (or contains) a runtime-computed value. */
  dynamic?: boolean;
  /** eval-exec: the argument is decoded at runtime (atob, base64 Buffer, fromCharCode). */
  decoded?: boolean;
  /**
   * eval-exec: a process started directly (no shell, not an interpreter
   * given code) — what runs is a program with arguments, not code built at
   * runtime.
   */
  noShell?: boolean;
  /**
   * eval-exec: an interpreter or shell started directly with literal code
   * (`python -c "import sys; …"`, or a constant holding the script) — the
   * code is fixed; what follows it is the code's argv.
   */
  fixedCode?: boolean;
  line: number;
  snippet: string;
  /** The whole line when `snippet` is a cut of it (see `cutLine`). */
  sourceLine?: string;
  description: string;
}

const SOURCES = new Set([
  'readFile', 'readFileSync', 'readdir', 'readdirSync',
  'createReadStream',
]);

const ENV_SOURCES = new Set(['env']);

/** Programs whose arguments go over the network (as in the Python analyzer). */
const NETWORK_PROGRAM = /^(?:curl|wget|nc|ncat|netcat|socat|scp|sftp|ftp|rsync|ssh|telnet)$/;

const SINKS = new Set([
  'fetch', 'request', 'get', 'post', 'put', 'patch',
  'send', 'write', 'emit',
]);

const NETWORK_MODULES = new Set([
  'http', 'https', 'net', 'dgram', 'axios', 'got',
  'node-fetch', 'undici', 'request',
]);

const EXEC_FUNCTIONS = new Set([
  'eval', 'Function',
  'exec', 'execSync', 'spawn', 'spawnSync',
  'execFile', 'execFileSync', 'fork',
]);

const SENSITIVE_PATHS = [
  /\/\.ssh\//i,
  /\/\.aws\//i,
  /\/\.gnupg\//i,
  /\/\.kube\//i,
  /\/\.env/i,
  /\/etc\/(?:passwd|shadow|hosts)/i,
  /\/\.docker\/config/i,
  // credential stores by file name — not any path containing the word
  // (`docs/secretary-notes.md`, `credentials-guide.md`)
  /(?:^|[\/])\.?credentials(?:\.(?:json|toml|ya?ml|csv|ini|db))?$/i,
  /(?:^|[\/])\.?secrets?(?:\.(?:json|toml|ya?ml|env|txt))?$/i,
  /client_secret[\w.-]*\.json$/i,
  /(?:^|[\/])\.(?:git-credentials|netrc|pgpass)$/i,
];

// Several checks (SKL-001/003/006/008/010, MCP-004/006) analyze the same
// files in one scan; parse each distinct file once. Keyed by a content hash so
// the cache never holds file contents.
const MAX_CACHED_ANALYSES = 10_000;
const analysisCache = new Map<string, DataFlowResult[]>();

/** HTTP clients whose request functions take the destination URL first (`axios.post(url, body, config)`, `https.request(url, opts)`). */
const HTTP_CLIENT_MODULE = /^(?:node:)?(?:https?|axios|got|node-fetch|undici|request|superagent|ky|cross-fetch|isomorphic-fetch)$/;
const HTTP_REQUEST_METHODS = new Set(['fetch', 'request', 'get', 'post', 'put', 'patch', 'delete', 'head']);
const FETCH_MODULE = /^(?:node-fetch|undici|cross-fetch|isomorphic-fetch)$/;
const GLOBAL_SCOPES = new Set(['globalThis', 'window', 'global', 'self']);

const escapeRegExp = (text: string): string => text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/**
 * A real HTTP request whose first argument is where it goes: the global
 * `fetch` (not a local function of that name), or a request method of an
 * imported HTTP client. A socket's `emit`/`send`/`write` is not — its first
 * argument is an event name or payload, and the peer is whoever it connected to.
 */
function httpRequestCall(p: NodePath): boolean {
  const call = p.node;
  if (call.type !== 'CallExpression') return false;
  const callee = call.callee;
  if (callee.type === 'Identifier') {
    if (callee.name !== 'fetch') return false;
    const binding = p.scope.getBinding('fetch');
    return !binding || FETCH_MODULE.test(bindingModule(binding) ?? '');
  }
  if (callee.type !== 'MemberExpression' || callee.computed || callee.property.type !== 'Identifier') return false;
  const method = callee.property.name;
  if (!HTTP_REQUEST_METHODS.has(method)) return false;
  // `require('axios').get(…)`
  const object = callee.object;
  if (object.type === 'CallExpression' && object.callee.type === 'Identifier' && object.callee.name === 'require'
    && !p.scope.getBinding('require') && object.arguments.length === 1 && object.arguments[0].type === 'StringLiteral') {
    return HTTP_CLIENT_MODULE.test(object.arguments[0].value);
  }
  if (object.type !== 'Identifier') return false;
  const binding = p.scope.getBinding(object.name);
  if (!binding) return method === 'fetch' && GLOBAL_SCOPES.has(object.name);
  return HTTP_CLIENT_MODULE.test(bindingModule(binding) ?? '');
}

/**
 * Request options that send a request somewhere other than its URL's host
 * (`hostname`, `host`, `socketPath`), through another resolver, agent or proxy
 * (`lookup`, `agent`, `proxy`, `dispatcher`), or without verifying the
 * server (`rejectUnauthorized`). `baseURL` is fine only on the vendor's host.
 */
const REDIRECT_OPTIONS = new Set([
  'host', 'hostname', 'socketPath', 'lookup', 'agent', 'httpAgent', 'httpsAgent', 'proxy', 'dispatcher', 'rejectUnauthorized',
  'createConnection', 'servername',
]);
/** `fetch = …`, `globalThis.fetch = …`, `window['fetch'] = …`, `Object.defineProperty(globalThis, 'fetch', …)`. */
const FETCH_ASSIGNMENT = /(?:^|[^\w$.])(?:(?:globalThis|window|self|global)\s*(?:\.\s*fetch|\[\s*['"`]fetch['"`]\s*\])|fetch)\s*(?:=(?!=)|\|\|=|\?\?=)|defineProperty\s*\(\s*(?:globalThis|window|self|global)\s*,\s*['"`]fetch['"`]/;

/**
 * Code that sends every request of the file somewhere else, whatever URL a
 * call names: fetch replaced through an alias (`const g = globalThis;
 * g.fetch = …`, `Object.assign(globalThis, { fetch })`), client interceptors
 * and defaults (axios `interceptors.request.use`, `defaults.proxy`), a global
 * dispatcher or agent (undici `setGlobalDispatcher`, `https.globalAgent`),
 * patched network modules (`https.request = …`), proxy/TLS environment
 * settings, or another DNS resolver. A vendor key in its own API's headers
 * then goes wherever that points.
 */
const GLOBAL_REDIRECT = new RegExp([
  // (assignments and calls, not mentions: a bundled client library defines
  // and reads its own `defaults`, `globalAgent` and `lookup`)
  String.raw`(?:\.\s*fetch|\[\s*['"\x60]fetch['"\x60]\s*\])\s*(?:=(?!=)|\|\|=|\?\?=)`,
  String.raw`\bObject\s*\.\s*(?:assign|defineProperty|defineProperties)\s*\(\s*(?:globalThis|window|self|global)\b[^;]{0,200}?\bfetch\b`,
  String.raw`\.\s*interceptors\s*\.\s*request\s*\.\s*use\s*\(`,
  String.raw`\.\s*defaults\s*\.\s*(?:proxy|httpAgent|httpsAgent|adapter|transport|socketPath|lookup|beforeRedirect|dispatcher|agent)\s*(?:=(?!=)|\|\|=|\?\?=)`,
  String.raw`\bObject\s*\.\s*assign\s*\(\s*[\w$.]*\bdefaults\s*,[^;]{0,200}?\b(?:proxy|httpAgent|httpsAgent|adapter|lookup|dispatcher|agent)\b`,
  String.raw`(?<!function\s{1,10})\bset(?:GlobalDispatcher|Servers)\s*\(`,
  String.raw`\bglobalAgent\s*(?:\.\s*[\w$]+\s*)*(?:=(?!=)|\|\|=|\?\?=)`,
  String.raw`(?:^|[^\w$.])(?:https?|http2|net|tls|dns)\s*\.\s*(?:request|get|connect|createConnection|lookup|Agent|checkServerIdentity)\s*=(?!=)`,
  String.raw`\b(?:HTTPS?_PROXY|ALL_PROXY|NO_PROXY|NODE_TLS_REJECT_UNAUTHORIZED|NODE_EXTRA_CA_CERTS|GLOBAL_AGENT_[A-Z_]+|SSL_CERT_FILE)\b['"\x60]?\s*\]?\s*(?:=(?!=)|\|\|=|\?\?=)`,
  String.raw`\bObject\s*\.\s*assign\s*\(\s*process\s*\.\s*env\b[^;]{0,200}?(?:PROXY|NODE_TLS_REJECT_UNAUTHORIZED|NODE_EXTRA_CA_CERTS)`,
].join('|'), 'i');

function isFetchCallee(callee: Node): boolean {
  if (callee.type === 'Identifier') return callee.name === 'fetch';
  return callee.type === 'MemberExpression' && !callee.computed && callee.property.type === 'Identifier' && callee.property.name === 'fetch';
}

/**
 * Whether any options argument redirects the request (REDIRECT_OPTIONS), or
 * can't be seen: a spread, a computed key, or a variable that isn't a constant
 * object literal. The body argument of `post/put/patch(url, body, config)` is
 * data, not options.
 */
function redirectedRequest(args: Node[], p: NodePath, domains: readonly string[]): boolean {
  const call = p.node;
  const method = call.type === 'CallExpression' && call.callee.type === 'MemberExpression' && call.callee.property.type === 'Identifier'
    ? call.callee.property.name : '';
  const bodyIndex = /^(?:post|put|patch)$/.test(method) ? 1 : -1;
  for (let i = 1; i < args.length; i++) {
    let arg = args[i];
    if (arg.type === 'Identifier') {
      const binding = p.scope.getBinding(arg.name);
      const init = binding?.constant && binding.path.node.type === 'VariableDeclarator' ? binding.path.node.init : undefined;
      // an options object changed after it was built (`opts.hostname = …`, `Object.assign(opts, …)`) is not what its literal says
      if (init?.type === 'ObjectExpression' && !changedElsewhere(binding!, p)) arg = init;
      else if (i === bodyIndex) continue;
      else return true;
    }
    if (arg.type !== 'ObjectExpression') {
      if (i === bodyIndex) continue;
      // A callback (`https.get(url, opts, res => …)`) carries no options
      if (arg.type === 'ArrowFunctionExpression' || arg.type === 'FunctionExpression') continue;
      return true;
    }
    if (i === bodyIndex) continue;
    for (const prop of arg.properties) {
      if (prop.type !== 'ObjectProperty' && prop.type !== 'ObjectMethod') return true;
      if (prop.computed) return true;
      const key = prop.key.type === 'Identifier' ? prop.key.name : prop.key.type === 'StringLiteral' ? prop.key.value : '';
      if (REDIRECT_OPTIONS.has(key)) return true;
      if (key === 'baseURL' || key === 'prefixUrl') {
        const value = prop.type === 'ObjectProperty' && prop.value.type === 'StringLiteral' ? prop.value.value : '';
        try {
          const u = new URL(value);
          const h = u.hostname.toLowerCase();
          if (u.protocol !== 'https:' || !domains.some((d) => h === d || h.endsWith(`.${d}`))) return true;
        } catch {
          return true;
        }
      }
    }
  }
  return false;
}

/**
 * Whether an object bound to `binding` may be changed outside the request
 * call `call`: a property assigned, updated or deleted, a method called on
 * it, or the object handed to anything but another request (a helper, an
 * alias, `Object.assign(opts, …)`). Reading a property or spreading it
 * changes nothing.
 */
function changedElsewhere(binding: Binding, call: NodePath): boolean {
  for (const ref of binding.referencePaths) {
    if (ref.findParent((q) => q.node === call.node)) continue;
    let top: NodePath = ref;
    while (top.parentPath?.isMemberExpression() && top.key === 'object') top = top.parentPath;
    const parent = top.parentPath;
    if (!parent) continue;
    if (top !== ref) {
      // `opts.x = …`, `opts.x++`, `delete opts.x`, `opts.headers.set(…)`
      if ((parent.isAssignmentExpression() && top.key === 'left') || parent.isUpdateExpression()
        || (parent.isUnaryExpression() && parent.node.operator === 'delete')
        || (parent.isCallExpression() && top.key === 'callee')) return true;
      continue;
    }
    if (parent.isSpreadElement() || parent.isMemberExpression()) continue;
    if (parent.isCallExpression() && top.key !== 'callee' && httpRequestCall(parent)) continue;
    if (parent.isIfStatement() || parent.isLogicalExpression() || parent.isUnaryExpression() || parent.isBinaryExpression()) continue;
    return true;
  }
  return false;
}

export function analyzeCode(code: string, filename = 'unknown.js'): DataFlowResult[] {
  if (!mayBeJavaScript(filename)) return [];
  const key = `${filename}\0${createHash('sha1').update(code).digest('base64')}`;
  const cached = analysisCache.get(key);
  if (cached) return cached.map(r => ({ ...r }));
  // Per file: resolved npm packages are several modules joined with headers,
  // which don't parse as one program.
  const results = sourceChunks(code).flatMap((chunk) =>
    analyzeUncached(chunk.code).map((r) => ({ ...r, line: r.line + chunk.startLine - 1 })));
  if (analysisCache.size >= MAX_CACHED_ANALYSES) {
    analysisCache.delete(analysisCache.keys().next().value!);
  }
  analysisCache.set(key, results);
  return results.map(r => ({ ...r }));
}

/**
 * First line (1-based) of code in `code` that defeats the parser — a
 * statement nested or chained deeply enough to overflow it, which the AST
 * checks skip — or undefined. Shares the parse with analyzeCode.
 */
export function analysisEvasion(code: string, filename = 'unknown.js'): { line: number; whole: boolean } | undefined {
  if (!mayBeJavaScript(filename)) return undefined;
  analyzeCode(code, filename);
  for (const chunk of sourceChunks(code)) {
    const rec = recordedEvasion(chunk.code) ?? (() => {
      const r = parseLenientReport(chunk.code);
      return { lines: r.evaded, whole: r.overflow && !r.ast };
    })();
    if (rec.whole) return { line: chunk.startLine, whole: true };
    if (rec.lines.length > 0) return { line: rec.lines[0] + chunk.startLine - 1, whole: false };
  }
  return undefined;
}

/**
 * Last resort when an overflow left no AST at all: a line-by-line look for
 * what the AST checks would have reported — exec/eval calls, and a request
 * or send carrying file contents or the environment — so a file built to
 * crash the parser doesn't come out clean.
 */
export function lineFallback(code: string): DataFlowResult[] {
  const out: DataFlowResult[] = [];
  const execCall = /(?<![\w$.])(?:eval|exec|execSync|spawn|spawnSync|execFile|execFileSync)\s*\(|\.(?:exec|execSync|spawn|spawnSync|execFile|execFileSync)\s*\(|\bnew\s+Function\s*\(/;
  const send = /(?<![\w$])fetch\s*\(|\.(?:post|put|patch|request|send|write)\s*\(/;
  const source = /\breadFile(?:Sync)?\s*\(|(?<![\w$])process\.env\b/;
  const sourceVars = new Set<string>();
  code.split('\n').forEach((text, i) => {
    if (text.length > 4000) return; // the over-deep line itself
    const decl = /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([^;]*)/.exec(text);
    if (decl && source.test(decl[2])) sourceVars.add(decl[1]);
    const snippet = cutLine(text.trim());
    if (execCall.test(text)) {
      out.push({ type: 'eval-exec', line: i + 1, ...snippet, description: 'Command or code execution (line scan — the file overflows the parser)', dynamic: true });
    }
    if (send.test(text)) {
      const carried = source.test(text) ? 'inline source' : [...sourceVars].find(v => new RegExp(`(?<![\\w$.])${v}(?![\\w$])`).test(text));
      if (carried) {
        out.push({ type: 'source-to-sink', source: carried, sourceKind: 'file', line: i + 1, ...snippet, description: `Data flows from "${carried}" to a network call (line scan — the file overflows the parser)` });
      }
    }
  });
  return out;
}

function analyzeUncached(code: string): DataFlowResult[] {
  const results: DataFlowResult[] = [];
  let ast: JsAst;
  // Split once: re-splitting the file per call expression made analysis
  // quadratic in file size.
  let lines: string[] | undefined;
  const lineText = (line: number): string => (lines ??= code.split('\n'))[line - 1]?.trim() ?? '';

  const report = parseLenientReport(code);
  if (!report.ast) return report.overflow ? lineFallback(code) : results;
  ast = report.ast;
  // Module-level `const NAME = 'literal'`: a program named through a constant
  // (`spawnSync(FFMPEG, args)`) is as known as one written inline
  const constStrings = new Map<string, string>();
  for (const stmt of ast.program.body) {
    const decl = stmt.type === 'ExportNamedDeclaration' ? stmt.declaration : stmt;
    if (decl?.type !== 'VariableDeclaration' || decl.kind !== 'const') continue;
    for (const d of decl.declarations) {
      if (d.id.type !== 'Identifier' || !d.init) continue;
      if (d.init.type === 'StringLiteral') constStrings.set(d.id.name, d.init.value);
      else if (d.init.type === 'TemplateLiteral' && d.init.expressions.length === 0) constStrings.set(d.id.name, d.init.quasis[0]?.value.cooked ?? '');
    }
  }

  // Variable → what it holds. Matched in sink arguments as a whole identifier:
  // a substring test made a minified `o` match every `output`.
  const sourceVars = new Map<string, 'file' | 'env'>();
  const mentions = (argStr: string, name: string): boolean =>
    new RegExp(`(?<![\\w$.])${escapeRegExp(name)}(?![\\w$])`).test(argStr);
  const networkImports = new Set<string>();
  // Environment values written inline in a request (`body: JSON.stringify(process.env)`,
  // `axios.post(url, process.env.KEY)`), by the rules of the Python analyzer:
  // the whole environment anywhere in the call, a single value in the
  // request body — or anywhere in a request when it is a credential
  // (ownedCredential: `?k=${process.env.AWS_SECRET_ACCESS_KEY}`, a header to
  // another host; a vendorless one outside the headers: genericCredentialAuth).
  const inlineEnv = (args: Node[], sinkName: string): string[] => inlineSources(args, sinkName, false)
    .filter(([, kind]) => kind === 'env').map(([name]) => name);
  /**
   * Sources written inline in a sink call: file contents (`readFileSync(…)`)
   * and the whole environment anywhere in it; a single environment value in
   * a request body, or anywhere in a `request` when it is a credential whose
   * home is known (ownedCredential) — or, for a network program's argv
   * (`allEnv`), any value anywhere.
   */
  const inlineSources = (args: Node[], sinkName: string, allEnv: boolean, request = false): Array<[string, 'file' | 'env']> => {
    if (args.length === 0) return [];
    const all = code.slice(args[0].start ?? 0, args[args.length - 1].end ?? 0);
    const out: Array<[string, 'file' | 'env']> = [];
    const file = all.match(/(?<![\w$])(?:fs\.)?(?:promises\.)?readFile(?:Sync)?\s*\(/);
    if (file) out.push([`${file[0].replace(/\s*\($/, '')}()`, 'file']);
    if (/(?<![\w$])(?<!(?:^|[^.])\.)process\.env(?![\w$]|\s*(?:\.|\[|\?\.))/.test(all)) out.push(['process.env', 'env']);
    const body = allEnv ? all : requestBody(args, sinkName);
    const seen = new Set<string>();
    for (const m of all.matchAll(/(?<![\w$.])process\.env(?:\.[A-Za-z_$][\w$]*|\[[^\]]+\])/g)) {
      if (seen.has(m[0])) continue;
      const name = envNameOf(m[0]);
      // (a credential not tied to a vendor is let through here and judged by where it sits: genericCredentialAuth)
      if (!mentions(body, m[0]) && !(request && name !== undefined && credentialEnvName(name))) continue;
      seen.add(m[0]);
      out.push([m[0], 'env']);
    }
    return out;
  };
  /** Request options that say a call is an HTTP request even when its client can't be resolved. */
  const REQUEST_OPTION = /^(?:headers|params|searchParams|query|qs|auth|cookies?|method)$/;
  /**
   * Whether a member-call sink is an HTTP request — an imported client's
   * request method, a literal URL first, or request options — rather than a
   * `get`/`send` of something else (`cache.get(…)`, `map.post…`).
   */
  const requestLike = (args: Node[], p: NodePath): boolean => httpRequestCall(p)
    || (args[0] !== undefined && /^[`'"](?:https?|wss?):\/\//i.test(code.slice(args[0].start ?? 0, args[0].end ?? 0)))
    || args.some((a) => a.type === 'ObjectExpression' && a.properties.some((pr) => pr.type === 'ObjectProperty'
      && REQUEST_OPTION.test(pr.key.type === 'Identifier' ? pr.key.name : pr.key.type === 'StringLiteral' ? pr.key.value : '')));
  /**
   * An environment value named for a setting (`PORT`, `API_BASE_URL`, `HOME`)
   * that appears only in a call's first argument — the URL it goes to — picks
   * the address; it isn't data sent. Credentials by name, values in the body
   * or options, and values of unknown name still count. A destructured value
   * follows the inline rules instead: outside the body, only an ownedCredential.
   */
  const onlyAddressing = (args: Node[], sinkName: string, sourceVar: string, p: NodePath): boolean => {
    if (wholeEnvAt(p, sourceVar) || mentions(requestBody(args, sinkName), sourceVar)) return false;
    const name = envNameOf(sourceVar);
    // Destructured values follow the inline rules: outside the body, only a
    // credential (a vendorless one only outside the headers: genericCredentialAuth)
    if (destructuredEnv.has(sourceVar)) return name === undefined || !credentialEnvName(name);
    if (name === undefined || credentialEnvName(name)) return false;
    const rest = args.slice(1).map((a) => code.slice(a.start ?? 0, a.end ?? 0)).join(',');
    return !mentions(rest, sourceVar);
  };
  // Client sockets the code opens (`const ws = new WebSocket(url)`): `ws.send(…)`
  // goes to that remote endpoint, unlike a server socket answering its client
  const clientSockets = new Set<string>();
  // Variables holding the whole environment (`const e = process.env`, `{ ...process.env }`)
  // Variables holding the whole environment, by binding: minified code reuses
  // short names, and a parameter `t` in one function is not the `process.env`
  // copy `t` in another. Names only for unbound (global) assignments.
  const wholeEnvVars = new Set<string>();
  const wholeEnvBindings = new Set<object>();
  const wholeEnvAt = (p: NodePath, v: string): boolean => {
    if (v === 'process.env') return true;
    const binding = p.scope.getBinding(v);
    return binding ? wholeEnvBindings.has(binding) : wholeEnvVars.has(v);
  };
  const requestBody = (args: Node[], sinkName: string): string => {
    const text = (n: Node | undefined) => (n ? code.slice(n.start ?? 0, n.end ?? 0) : '');
    const parts: string[] = [];
    if (/^(?:send|write|emit)$/.test(sinkName)) parts.push(...args.map(text));
    if (/^(?:post|put|patch)$/.test(sinkName)) parts.push(text(args[1]));
    for (const a of args) {
      if (a.type !== 'ObjectExpression') continue;
      for (const p of a.properties) {
        if (p.type !== 'ObjectProperty') continue;
        const key = p.key.type === 'Identifier' ? p.key.name : p.key.type === 'StringLiteral' ? p.key.value : '';
        if (/^(?:body|data|json|form|payload)$/.test(key)) parts.push(text(p.value as Node));
      }
    }
    return parts.join(',');
  };
  // `const key = process.env.OPENAI_API_KEY` → OPENAI_API_KEY
  const envNames = new Map<string, string>();
  // Names bound by destructuring the environment (`const { API_KEY } = process.env`)
  const destructuredEnv = new Set<string>();
  // Options objects whose environment values all sit in their `headers` (`const opts = { headers: { Authorization: … } }`)
  const headerOptionVars = new Set<string>();
  // Variables holding environment values, by binding: minified code reuses
  // one-letter names, and the `u` holding a key is not every other `u`
  const carrierBindings = new Map<string, Set<object>>();
  const addBinding = (v: string, binding: object): void => {
    const set = carrierBindings.get(v);
    if (set) set.add(binding);
    else carrierBindings.set(v, new Set([binding]));
  };
  // Credentials an HTTP client carries into every request it makes, by the
  // client's binding: an instance built with them (`axios.create({ headers })`,
  // `got.extend(…)`, `ky.create(…)`) or defaults set on a client
  // (`axios.defaults.headers.common.Authorization = …`), with its base URL
  const clients = new Map<object, { creds: Array<{ source: string; envName?: string; slot: 'headers' | 'other' }>; base?: string }>();
  /** Environment values an expression carries: `process.env.X` and variables read from the environment. */
  const envRefs = (q: NodePath): Array<{ source: string; envName?: string }> => {
    const out: Array<{ source: string; envName?: string }> = [];
    const visit = (r: NodePath) => {
      if (r.isMemberExpression()) {
        const o = r.node.object;
        if (o.type === 'MemberExpression' && !o.computed && o.object.type === 'Identifier' && o.object.name === 'process'
          && o.property.type === 'Identifier' && o.property.name === 'env') {
          out.push({ source: code.slice(r.node.start ?? 0, r.node.end ?? 0), envName: memberName(r.node) });
        }
      } else if (r.isIdentifier() && r.isReferencedIdentifier() && sourceVars.get(r.node.name) === 'env'
        && !wholeEnvAt(r, r.node.name) && !otherBinding(r, r.node.name)) {
        out.push({ source: r.node.name, envName: envNames.get(r.node.name) });
      }
    };
    visit(q);
    q.traverse({ Function(f) { f.skip(); }, MemberExpression: visit, Identifier: visit });
    return out;
  };
  const clientOf = (b: object) => {
    let c = clients.get(b);
    if (!c) clients.set(b, (c = { creds: [] }));
    return c;
  };
  /** A client config's credentials and base URL (`{ baseURL, headers, auth, params }`). */
  const readClientConfig = (cfg: NodePath, b: object): void => {
    if (!cfg.isObjectExpression()) return;
    for (const prop of cfg.get('properties') as NodePath[]) {
      if (!prop.isObjectProperty() || prop.node.computed) continue;
      const k = prop.node.key;
      const key = k.type === 'Identifier' ? k.name : k.type === 'StringLiteral' ? k.value : '';
      const value = prop.get('value') as NodePath;
      if ((key === 'baseURL' || key === 'prefixUrl' || key === 'prefixURL') && value.isStringLiteral()) clientOf(b).base = value.node.value;
      const slot = key === 'headers' || key === 'auth' ? 'headers' : /^(?:params|searchParams|cookies?)$/.test(key) ? 'other' : undefined;
      if (slot) for (const r of envRefs(value)) clientOf(b).creds.push({ ...r, slot });
    }
  };
  /**
   * The verdict on a credential a client carries, for one request
   * `client.get(url, …)`: judged as if written in the request's headers
   * (or params) — a vendor's key to its own API and a vendorless key in the
   * headers are how the client authenticates; anything else is leaving.
   */
  const clientCredentialLeaves = (c: { envName?: string; slot: 'headers' | 'other' }, base: string | undefined, args: Node[], p: NodePath): boolean => {
    const name = c.envName;
    if (name === undefined || !credentialEnvName(name)) return false;
    if (!ownedCredential(name)) return c.slot !== 'headers';
    const domains = signingSecret(name) ? undefined : vendorApiDomains(name);
    if (!domains || c.slot !== 'headers' || redirectsAll() || redirectedRequest(args, p, domains)) return true;
    // where the request goes: an absolute URL wins over the client's base; a relative one is appended to it
    const parts = urlParts(args[0], p);
    if (parts.some((x) => typeof x !== 'string')) return true;
    const path = (parts as string[]).join('');
    const url = /^(?:[a-z][a-z\d+.-]*:)?\/\//i.test(path) ? path
      : base !== undefined ? `${base.replace(/\/+$/, '')}${path ? `/${path.replace(/^\/+/, '')}` : ''}` : undefined;
    return !onVendorHost(url, domains);
  };
  const otherBinding = (p: NodePath, v: string): boolean => {
    const bindings = carrierBindings.get(v);
    const binding = bindings && p.scope.getBinding(v);
    return bindings !== undefined && (binding === undefined || !bindings.has(binding));
  };
  // `process.env.KEY` / `process.env['KEY']` → KEY; a variable → the name it was read from
  const envNameOf = (sourceVar: string): string | undefined => {
    const m = /^process\.env(?:\.([A-Za-z_$][\w$]*)|\[\s*(['"`])([^'"`\]]+)\2\s*\])$/.exec(sourceVar);
    return m ? m[1] ?? m[3] : envNames.get(sourceVar);
  };
  /**
   * A single credential sent to the API it belongs to: an environment value
   * (`OPENAI_API_KEY`, inline or through a variable) that appears only in the
   * request's `headers` object, on a request to a literal https:// URL whose
   * host names the credential's vendor (OPENAI_… → api.openai.com,
   * GITHUB_… → api.github.com). That is how a key is used, not a leak; the
   * same key in a body, the URL, or headers to any other host still is. Only
   * for real HTTP requests (httpRequestCall) — a socket `emit('https://…')` or
   * a local `function fetch` sends it somewhere else.
   */
  const credentialToOwnApi = (args: Node[], sourceVar: string, sourceKind: 'file' | 'env', p: NodePath): boolean => {
    if (sourceKind !== 'env' || wholeEnvAt(p, sourceVar) || !httpRequestCall(p)) return false;
    // a signing secret (`GITHUB_WEBHOOK_SECRET`) is never how a request authenticates
    if (signingSecret(envNameOf(sourceVar))) return false;
    const domains = vendorApiDomains(envNameOf(sourceVar));
    if (!domains) return false;
    const envName = envNameOf(sourceVar);
    const name = escapeRegExp(sourceVar);
    const used = (text: string) => new RegExp(`(?<![\\w$])${name}(?![\\w$])`).test(text);
    // The URL as static text and computed parts: a literal, a module-level
    // constant (`const API = 'https://api.openai.com/v1'`), a template or a `+` chain
    const parts = urlParts(args[0], p);
    let url = '';
    const computed: Array<{ node: Node; before: string }> = [];
    for (const part of parts) {
      if (typeof part === 'string') url += part;
      else {
        computed.push({ node: part, before: url });
        url += '\0';
      }
    }
    if (computed.length > 0 && parts.length > 0) {
      // (the static text before the first computed part: `${BASE}` splits it into several strings)
      const origin = staticOrigin(url.split('\0')[0]);
      if (!origin || !onVendorHost(origin, domains)) return false;
    } else if (!onVendorHost(url, domains)) return false;
    if (redirectedRequest(args, p, domains)) return false;
    // A global fetch the file replaces (`globalThis.fetch = …`) goes wherever the replacement sends it
    const call = p.node;
    if (call.type === 'CallExpression' && isFetchCallee(call.callee) && FETCH_ASSIGNMENT.test(code)) return false;
    // …and so does every request when the file redirects them all (interceptors, proxies, dispatchers, TLS/DNS)
    if (redirectsAll()) return false;
    // Where the value is written: inside the request's headers, or in the
    // URL where the vendor documents it (vendorUrlSlot: Google `?key=`, Telegram `/bot<token>/`)
    const allowed = headerSpans(args, false);
    for (const { node, before } of computed) {
      const value = node.type === 'CallExpression' && node.callee.type === 'Identifier' && /^encodeURI(?:Component)?$/.test(node.callee.name)
        && node.arguments.length === 1 ? node.arguments[0] as Node : node;
      // (the host is static — staticOrigin — so a computed path part before the slot can't move it)
      if (code.slice(value.start ?? 0, value.end ?? 0) === sourceVar && vendorUrlSlot(envName, before.replace(/\0/g, '')))
        allowed.push([node.start ?? 0, node.end ?? 0]);
    }
    if (allowed.length === 0) return false;
    const start = args[0].start ?? 0;
    let outside = code.slice(start, args[args.length - 1].end ?? 0);
    // Text, not code: `?key=` in the URL is not the variable `key`
    const text: Array<[number, number]> = [];
    p.traverse({
      // (a computed key is code: `process.env['KEY']`)
      StringLiteral(q) { if (!(q.parentPath.isMemberExpression() && q.key === 'property')) text.push([q.node.start ?? 0, q.node.end ?? 0]); },
      TemplateElement(q) { text.push([q.node.start ?? 0, q.node.end ?? 0]); },
    });
    for (const [from, to] of [...allowed, ...text]) {
      if (from < start || to > start + outside.length) continue;
      outside = outside.slice(0, from - start) + ' '.repeat(to - from) + outside.slice(to - start);
    }
    return !used(outside) && allowed.some(([from, to]) => used(code.slice(from, to)));
  };
  let redirects: boolean | undefined;
  const redirectsAll = (): boolean => (redirects ??= GLOBAL_REDIRECT.test(code));
  /**
   * Where a request carries credentials: its `headers` (an object, or a
   * variable holding one — `{ headers }`, `headers: h`), an options variable
   * whose headers hold the value (`const opts = { headers: {…} }`), and —
   * with `auth` — the `auth` option (Basic credentials). Source spans.
   */
  const headerSpans = (args: Node[], auth: boolean): Array<[number, number]> => {
    const out: Array<[number, number]> = [];
    args.forEach((a, i) => {
      if (i > 0 && a.type === 'Identifier' && headerOptionVars.has(a.name)) out.push([a.start ?? 0, a.end ?? 0]);
      if (a.type !== 'ObjectExpression') return;
      for (const prop of a.properties) {
        if (prop.type !== 'ObjectProperty') continue;
        const key = prop.key.type === 'Identifier' ? prop.key.name : prop.key.type === 'StringLiteral' ? prop.key.value : '';
        if ((key === 'headers' || (auth && key === 'auth')) && (prop.value.type === 'ObjectExpression' || prop.value.type === 'Identifier')) {
          out.push([prop.value.start ?? 0, prop.value.end ?? 0]);
        }
      }
    });
    return out;
  };
  /**
   * A credential that isn't tied to one vendor (`API_KEY`, `MY_TOKEN`) sent
   * only in a request's headers or `auth`: how the skill authenticates to
   * whatever API it calls (vendorless, so there is no host to hold it to).
   * The same value in the URL, query or another option is leaving.
   */
  const genericCredentialAuth = (args: Node[], sourceVar: string, p: NodePath): boolean => {
    const name = envNameOf(sourceVar);
    if (name === undefined || !credentialEnvName(name) || ownedCredential(name) || wholeEnvAt(p, sourceVar)) return false;
    if (!requestLike(args, p)) return false;
    const spans = headerSpans(args, true);
    if (spans.length === 0 || args.length === 0) return false;
    const start = args[0].start ?? 0;
    let outside = code.slice(start, args[args.length - 1].end ?? 0);
    // and text, not code: `?token=` in the URL is not the variable `token`
    const text: Array<[number, number]> = [];
    p.traverse({
      StringLiteral(q) { if (!(q.parentPath.isMemberExpression() && q.key === 'property')) text.push([q.node.start ?? 0, q.node.end ?? 0]); },
      TemplateElement(q) { text.push([q.node.start ?? 0, q.node.end ?? 0]); },
    });
    for (const [from, to] of [...spans, ...text]) {
      if (from < start || to > start + outside.length) continue;
      outside = outside.slice(0, from - start) + ' '.repeat(to - from) + outside.slice(to - start);
    }
    const used = (text: string) => new RegExp(`(?<![\\w$.])${escapeRegExp(sourceVar)}(?![\\w$])`).test(text);
    return !used(outside) && spans.some(([from, to]) => used(code.slice(from, to)));
  };
  /**
   * A request URL as static text and computed parts, in order: a string or
   * template literal, a variable bound once to one (module-level or local:
   * `const endpoint = 'https://api.openai.com/v1'` inside the function), a
   * `+` chain of them, or `new URL(path, base)` with a static base and a path
   * that can't leave its host. Anything else is one computed part.
   */
  const urlParts = (n: Node | undefined, p: NodePath, depth = 0): Array<string | Node> => {
    if (!n) return [];
    if (n.type === 'StringLiteral') return [n.value];
    if (depth >= 20) return [n];
    // `${BASE}/models`: each interpolation resolved like a `+` operand
    if (n.type === 'TemplateLiteral') {
      return n.quasis.flatMap((q, i) => (i < n.expressions.length
        ? [q.value.cooked ?? '', ...urlParts(n.expressions[i] as Node, p, depth + 1)] : [q.value.cooked ?? '']));
    }
    if (n.type === 'Identifier') {
      const binding = p.scope.getBinding(n.name);
      if (!binding) return [n];
      if (constStrings.has(n.name) && binding.scope.path.isProgram()) return [constStrings.get(n.name)!];
      // bound once (const, or let/var never reassigned), by a plain declarator
      // (only to a URL being built: a variable holding a value read elsewhere — an env credential — is itself the part)
      const decl = binding.path;
      if (!binding.constant || !decl.isVariableDeclarator() || decl.node.id.type !== 'Identifier' || !decl.node.init) return [n];
      if (decl.parentPath?.parentPath?.isForXStatement() || !URL_INIT.has(decl.node.init.type)) return [n];
      return urlParts(decl.node.init, decl, depth + 1);
    }
    if (n.type === 'BinaryExpression' && n.operator === '+') {
      return [...urlParts(n.left as Node, p, depth + 1), ...urlParts(n.right, p, depth + 1)];
    }
    if (n.type === 'NewExpression' && n.callee.type === 'Identifier' && n.callee.name === 'URL' && !p.scope.getBinding('URL')
      && n.arguments.length >= 1 && n.arguments.length <= 2 && n.arguments.every((a) => a.type !== 'SpreadElement')) {
      const path = urlParts(n.arguments[0] as Node, p, depth + 1);
      if (n.arguments.length === 1) return path;
      const base = urlParts(n.arguments[1] as Node, p, depth + 1);
      if (base.some((b) => typeof b !== 'string')) return [n];
      const head = typeof path[0] === 'string' ? path[0] : undefined;
      // `/v1/models` resolves under the base's host; `//host`, `/\\host` or an absolute URL doesn't
      if (head === undefined || !/^\/[^/\\]/.test(head)) return [n];
      try {
        return [new URL(head, (base as string[]).join('')).href, ...path.slice(1)];
      } catch {
        return [n];
      }
    }
    return [n];
  };
  // Subset of sinks that spawn processes (child_process) rather than open connections
  const processImports = new Set<string>();
  // `import 'zx/globals'` (or a zx script) puts `$` on the global object
  const zxGlobals = ast.program.body.some(st => st.type === 'ImportDeclaration' && /^zx(?:\/globals)?$/.test(st.source.value) && st.specifiers.length === 0)
    || /^#!.*\bzx\b/.test(code);

  try {
    traverse(ast, {
      ImportDeclaration(path) {
        const source = path.node.source.value;
        if (NETWORK_MODULES.has(source)) {
          for (const spec of path.node.specifiers) {
            networkImports.add(spec.local.name);
          }
        }
        if (source === 'child_process') {
          // Still a sink (spawned commands can exfiltrate), but a process one
          for (const spec of path.node.specifiers) {
            networkImports.add(spec.local.name);
            processImports.add(spec.local.name);
          }
        }
      },

      CallExpression(path) {
        const node = path.node;
        const line = node.loc?.start.line ?? 0;
        const snippet = lineText(line);

        // Detect eval/exec — aliased, destructured, required inline or
        // dynamically imported child_process, execa/shelljs, indirect eval —
        // and any bare call named like one.
        const sink = sinkCallee(path);
        if (sink || (node.callee.type === 'Identifier' && EXEC_FUNCTIONS.has(node.callee.name))) {
          const name = sink?.display ?? (node.callee as { name: string }).name;
          results.push({
            type: 'eval-exec',
            line,
            ...cutLine(snippet),
            description: sink && node.callee.type === 'MemberExpression' && sink.kind === 'process'
              ? `${name}() — command execution`
              : `${name}() call detected`,
            ...commandText(node.arguments),
            ...(runsDirectly(sink?.fn ?? name, path, constStrings) ? { noShell: true } : {}),
          });
          if (sink?.kind === 'process' || !sink) {
            // What the process gets: file contents or the whole environment in
            // its arguments, or — for a network client (curl, nc, scp…) — any
            // environment value: `execFile('curl', ['-d', JSON.stringify(process.env), url])`
            // argv only: an options object (`{ env: process.env, cwd }`) configures
            // the child, it isn't data the child receives
            // (and a callback isn't argv either)
            const args = (node.arguments as Node[]).filter(a =>
              a.type !== 'ObjectExpression' && a.type !== 'FunctionExpression' && a.type !== 'ArrowFunctionExpression');
            const first = args[0];
            const program = first?.type === 'StringLiteral' ? first.value
              : first?.type === 'Identifier' ? constStrings.get(first.name) : undefined;
            const network = program !== undefined && NETWORK_PROGRAM.test(program.split('/').pop() ?? '');
            const pairs = inlineSources(args, name, network);
            // Variables only for a bare call: member calls (`cp.exec(x)`) are
            // matched against tracked variables in the sink branch below
            // Each argument's own text: a span from first to last argument took
            // in an options object between them (`execFile(p, argv, {env}, cb)`)
            const argStr = args.map(a => code.slice(a.start ?? 0, a.end ?? 0)).join(' ');
            if (node.callee.type === 'Identifier') {
              for (const [v, kind] of sourceVars) {
                if ((kind === 'file' || network || wholeEnvAt(path, v)) && mentions(argStr, v) && !pairs.some(([n]) => n === v)) pairs.push([v, kind]);
              }
            }
            for (const [sourceVar, sourceKind] of pairs) {
              if (sourceKind === 'env' && !wholeEnvAt(path, sourceVar) && !network) continue;
              results.push({
                type: 'source-to-sink',
                source: sourceVar,
                sourceKind,
                ...(sourceKind === 'env' && wholeEnvAt(path, sourceVar) ? { wholeEnv: true } : {}),
                sink: name,
                line,
                ...cutLine(snippet),
                description: network
                  ? `Data flows from "${sourceVar}" to network program "${program}"`
                  : `Data flows from "${sourceVar}" into process execution "${name}"`,
              });
            }
          }
        }

        // Detect require('child_process')
        if (
          node.callee.type === 'Identifier' &&
          node.callee.name === 'require' &&
          node.arguments[0]?.type === 'StringLiteral'
        ) {
          const mod = node.arguments[0].value;
          if (NETWORK_MODULES.has(mod) || mod === 'child_process') {
            networkImports.add(mod);
          }
        }

        // Detect standalone readFile('sensitive-path') calls (from named imports)
        if (node.callee.type === 'Identifier' && SOURCES.has(node.callee.name)) {
          const firstArg = node.arguments[0];
          if (firstArg?.type === 'StringLiteral') {
            for (const pattern of SENSITIVE_PATHS) {
              if (pattern.test(firstArg.value)) {
                results.push({
                  type: 'fs-access',
                  source: firstArg.value,
                  line,
                  ...cutLine(snippet),
                  description: `Reading sensitive path: ${firstArg.value}`,
                });
              }
            }
          }
          // Track variable assignment for data-flow
          const parent = path.parent;
          if (parent?.type === 'VariableDeclarator' && parent.id.type === 'Identifier') {
            sourceVars.set(parent.id.name, 'file');
          }
        }

        // Detect member call expressions: obj.method()
        if (node.callee.type === 'MemberExpression') {
          const prop = node.callee.property;
          const propName = prop.type === 'Identifier' ? prop.name : '';

          // Source detection: fs.readFile, fs.readFileSync, etc.
          if (SOURCES.has(propName)) {
            // Check if reading sensitive paths
            const firstArg = node.arguments[0];
            if (firstArg?.type === 'StringLiteral') {
              for (const pattern of SENSITIVE_PATHS) {
                if (pattern.test(firstArg.value)) {
                  results.push({
                    type: 'fs-access',
                    source: firstArg.value,
                    line,
                    ...cutLine(snippet),
                    description: `Reading sensitive path: ${firstArg.value}`,
                  });
                }
              }
            }

            // Track variable assignment for data-flow
            const parent = path.parent;
            if (parent?.type === 'VariableDeclarator' && parent.id.type === 'Identifier') {
              sourceVars.set(parent.id.name, 'file');
            }
          }

          // Sink detection: fetch(), http.request(), ws.send()
          if (SINKS.has(propName) || networkImports.has(propName)) {
            // Check if any source variables flow into this call
            const argStr = code.slice(node.arguments[0]?.start ?? 0, node.arguments[node.arguments.length - 1]?.end ?? 0);
            const receiver = node.callee.object;
            const sinkObject = receiver.type === 'Identifier'
              ? receiver.name
              : receiver.type === 'MemberExpression' && receiver.property.type === 'Identifier' ? receiver.property.name : undefined;
            const processSink = processImports.has(propName) || EXEC_FUNCTIONS.has(propName);
            const callArgs = node.arguments as Node[];
            const request = !processSink && requestLike(callArgs, path);
            const inlinePairs = processSink ? [] : inlineSources(callArgs, propName, false, request);
            const inline = inlinePairs.map(([name]) => name);
            const socketClient = propName === 'send' && sinkObject !== undefined && clientSockets.has(sinkObject);
            for (const [sourceVar, sourceKind] of new Map<string, 'file' | 'env'>([...sourceVars, ...inlinePairs])) {
              if (inline.includes(sourceVar) || mentions(argStr, sourceVar)) {
                if (!inline.includes(sourceVar) && otherBinding(path, sourceVar)) continue;
                if (!processSink && credentialToOwnApi(callArgs, sourceVar, sourceKind, path)) continue;
                if (!processSink && sourceKind === 'env' && genericCredentialAuth(callArgs, sourceVar, path)) continue;
                if (!processSink && sourceKind === 'env' && onlyAddressing(callArgs, propName, sourceVar, path)) continue;
                results.push({
                  type: 'source-to-sink',
                  source: sourceVar,
                  sourceKind,
                  ...(sourceKind === 'env' && wholeEnvAt(path, sourceVar) ? { wholeEnv: true } : {}),
                  sink: propName,
                  ...(sinkObject ? { sinkObject } : {}),
                  ...(socketClient ? { socketClient } : {}),
                  line,
                  ...cutLine(snippet),
                  description: processImports.has(propName) || EXEC_FUNCTIONS.has(propName)
                    ? `Data flows from "${sourceVar}" into process execution "${propName}"`
                    : `Data flows from "${sourceVar}" to network sink "${propName}"`,
                });
              }
            }
            // What the client itself carries (`axios.create({ headers })`, `axios.defaults.headers…`)
            const client = !processSink && receiver.type === 'Identifier' && HTTP_REQUEST_METHODS.has(propName)
              ? clients.get(path.scope.getBinding(receiver.name) ?? {}) : undefined;
            for (const c of client?.creds ?? []) {
              if (results.some((r) => r.type === 'source-to-sink' && r.line === line && r.source === c.source)) continue;
              if (!clientCredentialLeaves(c, client!.base, callArgs, path)) continue;
              results.push({
                type: 'source-to-sink', source: c.source, sourceKind: 'env', sink: propName, sinkObject: receiver.type === 'Identifier' ? receiver.name : undefined,
                line, ...cutLine(snippet),
                description: `Data flows from "${c.source}" (carried by the client) to network sink "${propName}"`,
              });
            }
          }

          // process.env access
          if (
            propName === 'env' &&
            node.callee.object.type === 'Identifier' &&
            (node.callee.object as { name: string }).name === 'process'
          ) {
            sourceVars.set('process.env', 'env');
          }

          // Detect child_process methods (sinkCallee above covers resolvable ones)
          if (EXEC_FUNCTIONS.has(propName) && !sink) {
            const obj = node.callee.object;
            if (obj.type === 'Identifier' && (networkImports.has(obj.name) || obj.name === 'child_process')) {
              results.push({
                type: 'eval-exec',
                line,
                ...cutLine(snippet),
                description: `${obj.name}.${propName}() — command execution`,
                ...commandText(node.arguments),
                ...(runsDirectly(propName, path, constStrings) ? { noShell: true } : {}),
              });
            }
          }
        }

        // Detect standalone fetch/network calls
        if (node.callee.type === 'Identifier') {
          if (node.callee.name === 'fetch') {
            const firstArg = node.arguments[0];
            if (firstArg?.type === 'StringLiteral') {
              const url = firstArg.value;
              // A relative URL (`/api/items`, `./data.json`) stays on the
              // page's own origin; `//host/…` is protocol-relative and leaves it.
              const relative = /^(?:\/(?!\/)|\.\.?\/)/.test(url);
              if (!relative &&
                  !url.startsWith('http://localhost') &&
                  !url.startsWith('http://127.0.0.1') &&
                  !url.startsWith('https://')) {
                results.push({
                  type: 'suspicious-network',
                  sink: url,
                  line,
                  ...cutLine(snippet),
                  description: `Non-localhost HTTP or non-HTTPS fetch: ${url}`,
                });
              }
            }

            // Check data-flow into fetch
            const inlinePairs = inlineSources(node.arguments as Node[], 'fetch', false, true);
            const inline = inlinePairs.map(([name]) => name);
            for (const [sourceVar, sourceKind] of new Map<string, 'file' | 'env'>([...sourceVars, ...inlinePairs])) {
              const argStr = code.slice(
                node.arguments[0]?.start ?? 0,
                node.arguments[node.arguments.length - 1]?.end ?? 0,
              );
              if (inline.includes(sourceVar) || mentions(argStr, sourceVar)) {
                if (!inline.includes(sourceVar) && otherBinding(path, sourceVar)) continue;
                if (credentialToOwnApi(node.arguments as Node[], sourceVar, sourceKind, path)) continue;
                if (sourceKind === 'env' && genericCredentialAuth(node.arguments as Node[], sourceVar, path)) continue;
                if (sourceKind === 'env' && onlyAddressing(node.arguments as Node[], 'fetch', sourceVar, path)) continue;
                results.push({
                  type: 'source-to-sink',
                  source: sourceVar,
                  sourceKind,
                  ...(sourceKind === 'env' && wholeEnvAt(path, sourceVar) ? { wholeEnv: true } : {}),
                  sink: 'fetch',
                  line,
                  ...cutLine(snippet),
                  description: `Data flows from "${sourceVar}" to fetch()`,
                });
              }
            }
          }
        }
      },

      // `axios.defaults.headers.common.Authorization = key`, `api.defaults.auth = {…}`, `axios.defaults.baseURL = '…'`
      AssignmentExpression(path) {
        if (path.node.operator !== '=') return;
        const chain: string[] = [];
        let left: Node = path.node.left;
        while (left.type === 'MemberExpression') {
          chain.unshift(memberName(left) ?? '');
          left = left.object;
        }
        if (left.type !== 'Identifier' || chain[0] !== 'defaults') return;
        const binding = path.scope.getBinding(left.name);
        if (!binding || !(clients.has(binding) || HTTP_CLIENT_MODULE.test(bindingModule(binding) ?? ''))) return;
        const right = path.get('right') as NodePath;
        if (chain.length === 1) { readClientConfig(right, binding); return; }
        if ((chain[1] === 'baseURL' || chain[1] === 'prefixUrl') && right.isStringLiteral()) { clientOf(binding).base = right.node.value; return; }
        const slot = chain[1] === 'headers' || chain[1] === 'auth' ? 'headers' : /^(?:params|searchParams|cookies?)$/.test(chain[1]) ? 'other' : undefined;
        if (slot) for (const r of envRefs(right)) clientOf(binding).creds.push({ ...r, slot });
      },

      // Track variable assignments from sources
      VariableDeclarator(path) {
        const init = path.node.init;
        if (!init) return;
        const id = path.node.id;
        // `const api = axios.create({ baseURL, headers })` — a client carrying its config
        if (id.type === 'Identifier' && init.type === 'CallExpression' && init.callee.type === 'MemberExpression'
          && init.callee.object.type === 'Identifier' && /^(?:create|extend)$/.test(memberName(init.callee) ?? '')) {
          const parent = path.scope.getBinding(init.callee.object.name);
          const binding = path.scope.getBinding(id.name);
          if (parent && binding && (clients.has(parent) || /^(?:axios|got|ky|ky-universal)$/.test(bindingModule(parent) ?? ''))) {
            const inherited = clients.get(parent);
            const c = clientOf(binding);
            if (inherited) { c.creds.push(...inherited.creds); c.base = inherited.base; }
            readClientConfig((path.get('init') as NodePath).get('arguments.0') as NodePath, binding);
            return;
          }
        }
        // `const { AWS_SECRET_ACCESS_KEY, OPENAI_API_KEY: key = '', ...rest } = process.env`
        if (id.type === 'ObjectPattern') {
          if (init.type !== 'MemberExpression' || init.computed || init.object.type !== 'Identifier' || init.object.name !== 'process'
            || init.property.type !== 'Identifier' || init.property.name !== 'env') return;
          for (const prop of id.properties) {
            if (prop.type === 'RestElement') {
              if (prop.argument.type !== 'Identifier') continue;
              sourceVars.set(prop.argument.name, 'env');
              const binding = path.scope.getBinding(prop.argument.name);
              if (binding) wholeEnvBindings.add(binding);
              else wholeEnvVars.add(prop.argument.name);
              continue;
            }
            if (prop.computed) continue;
            const envName = prop.key.type === 'Identifier' ? prop.key.name : prop.key.type === 'StringLiteral' ? prop.key.value : undefined;
            const local = prop.value.type === 'AssignmentPattern' ? prop.value.left : prop.value;
            if (envName === undefined || local.type !== 'Identifier') continue;
            sourceVars.set(local.name, 'env');
            envNames.set(local.name, envName);
            destructuredEnv.add(local.name);
            const binding = path.scope.getBinding(local.name);
            if (binding) addBinding(local.name, binding);
          }
          return;
        }
        if (id.type !== 'Identifier') return;

        if (init.type === 'NewExpression' && (
          (init.callee.type === 'Identifier' && init.callee.name === 'WebSocket')
          || (init.callee.type === 'MemberExpression' && init.callee.property.type === 'Identifier' && init.callee.property.name === 'WebSocket')
        )) clientSockets.add(id.name);

        const initText = code.slice(init.start ?? 0, init.end ?? 0);
        // Assigned, spread, or copied/serialized whole (not passed to some other call)
        const copies = init.type !== 'CallExpression'
          || /^(?:JSON\.stringify|Object\.assign|Object\.entries|structuredClone)\s*\(/.test(initText);
        if (copies && /(?<![\w$])(?<!(?:^|[^.])\.)process\.env(?![\w$]|\s*(?:\.|\[|\?\.))/.test(initText)) {
          sourceVars.set(id.name, 'env');
          const binding = path.scope.getBinding(id.name);
          if (binding) wholeEnvBindings.add(binding);
          else wholeEnvVars.add(id.name);
        }

        // Track process.env.X assignments
        if (
          init.type === 'MemberExpression' &&
          init.object.type === 'MemberExpression' &&
          init.object.object.type === 'Identifier' &&
          (init.object.object as { name: string }).name === 'process' &&
          init.object.property.type === 'Identifier' &&
          init.object.property.name === 'env'
        ) {
          sourceVars.set(id.name, 'env');
          if (init.property.type === 'Identifier') envNames.set(id.name, init.property.name);
          else if (init.property.type === 'StringLiteral') envNames.set(id.name, init.property.value);
          const binding = path.scope.getBinding(id.name);
          if (binding) addBinding(id.name, binding);
          return;
        }

        // A value built from environment values — headers or options objects,
        // `Bearer ${key}`, `process.env.A || process.env.B` — carries them:
        // `const opts = { headers: { Authorization: `Bearer ${process.env.OPENAI_API_KEY}` } }`
        if (sourceVars.has(id.name) || !CARRIER_INIT.has(init.type)) return;
        const carried: Array<{ name: string; inHeaders: boolean }> = [];
        const headerValues = init.type === 'ObjectExpression'
          ? init.properties.filter((pr) => pr.type === 'ObjectProperty' && !pr.computed
            && ((pr.key.type === 'Identifier' && pr.key.name === 'headers') || (pr.key.type === 'StringLiteral' && pr.key.value === 'headers')))
            .map((pr) => (pr as { value: Node }).value)
          : [];
        const inHeaders = (q: NodePath) => headerValues.some((h) => (q.node.start ?? 0) >= (h.start ?? 0) && (q.node.end ?? 0) <= (h.end ?? 0));
        (path.get('init') as NodePath).traverse({
          Function(q) { q.skip(); },
          // a test or comparison yields a flag, not the value (`process.env.X === 'true'`, `process.env.X ? a : b`)
          BinaryExpression(q) { if (q.node.operator !== '+') q.skip(); },
          UnaryExpression(q) { q.skip(); },
          ConditionalExpression(q) { q.get('test').skip(); },
          MemberExpression(q) {
            const name = q.node.object.type === 'MemberExpression' && !q.node.object.computed
              && q.node.object.object.type === 'Identifier' && q.node.object.object.name === 'process'
              && q.node.object.property.type === 'Identifier' && q.node.object.property.name === 'env' ? memberName(q.node) : undefined;
            if (name !== undefined) carried.push({ name, inHeaders: inHeaders(q) });
          },
          Identifier(q) {
            if (!q.isReferencedIdentifier() || sourceVars.get(q.node.name) !== 'env' || wholeEnvAt(q, q.node.name)) return;
            const name = envNames.get(q.node.name);
            if (name !== undefined) carried.push({ name, inHeaders: inHeaders(q) });
          },
        });
        // (credentials only: a setting carried into a value — a port, a base URL — was never data)
        const names = carried.map((c) => c.name).filter((n) => credentialEnvName(n));
        if (names.length === 0) return;
        sourceVars.set(id.name, 'env');
        envNames.set(id.name, names.find((n) => ownedCredential(n)) ?? names[0]);
        const binding = path.scope.getBinding(id.name);
        if (binding) addBinding(id.name, binding);
        if (carried.filter((c) => credentialEnvName(c.name)).every((c) => c.inHeaders)) headerOptionVars.add(id.name);
      },

      // zx / execa `$\`cmd ${arg}\``: a command run through a shell, each
      // interpolation quoted as one argument
      TaggedTemplateExpression(path) {
        const tag = path.node.tag;
        const fn = tag.type === 'CallExpression' ? tag.callee : tag.type === 'MemberExpression' && memberIs(tag, 'sync') ? tag.object : tag;
        if (fn.type !== 'Identifier' || fn.name !== '$') return;
        const mod = bindingModule(path.scope.getBinding('$'));
        if (mod ? !/^(?:zx(?:\/core)?|execa)$/.test(mod) : !zxGlobals) return;
        const line = path.node.loc?.start.line ?? 0;
        const quasi = path.node.quasi;
        const parts = quasi.quasis.map((q, i) => (q.value.cooked ?? '') + (i < quasi.expressions.length ? '${…}' : '')).join('');
        const program = (quasi.quasis[0]?.value.cooked ?? '').trim().split(/\s+/)[0] ?? '';
        const dynamic = quasi.expressions.length > 0;
        results.push({
          type: 'eval-exec',
          line,
          ...cutLine(lineText(line)),
          description: `${mod ?? 'zx'} $\`…\` — command execution`,
          ...(parts.trim() ? { command: parts.trim() } : {}),
          ...(dynamic ? { dynamic: true } : {}),
          // The program is written out and interpolations are quoted: unless it
          // is a shell or interpreter, what runs is that program with arguments
          ...(dynamic && program && !program.includes('${') && !SHELL_OR_INTERPRETER.test(program) ? { noShell: true } : {}),
        });
      },

      // Detect new Function() and new WebSocket()
      NewExpression(path) {
        const node = path.node;
        // new vm.Script(code) / new (require('vm').Script)(code)
        const vmSink = node.callee.type !== 'Identifier' ? sinkCallee(path) : undefined;
        if (vmSink?.kind === 'code') {
          const line = node.loc?.start.line ?? 0;
          results.push({
            type: 'eval-exec',
            line,
            ...cutLine(lineText(line)),
            description: `new ${vmSink.display}() — dynamic code execution`,
            ...commandText(node.arguments),
          });
        }
        if (node.callee.type === 'Identifier' && node.callee.name === 'Function') {
          const line = node.loc?.start.line ?? 0;
          const snippet = lineText(line);
          results.push({
            type: 'eval-exec',
            line,
            ...cutLine(snippet),
            description: 'new Function() constructor — dynamic code execution',
            ...commandText(node.arguments),
          });
        }
        if (node.callee.type === 'Identifier' && node.callee.name === 'WebSocket') {
          const line = node.loc?.start.line ?? 0;
          const snippet = lineText(line);
          results.push({
            type: 'suspicious-network',
            sink: 'WebSocket',
            line,
            ...cutLine(snippet),
            description: 'WebSocket connection created',
          });
        }
      },
    });
  } catch {
    // Traverse errors shouldn't crash the analysis
  }

  for (const r of results) {
    if (r.type === 'source-to-sink' && r.sourceKind === 'env' && r.source === 'process.env') r.wholeEnv = true;
  }
  mergeFlows(ast, results, lineText);
  return results;
}

/** Expressions a URL variable is built from (`const endpoint = 'https://…'`, `base + path`, `new URL(…)`). */
const URL_INIT = new Set(['StringLiteral', 'TemplateLiteral', 'BinaryExpression', 'NewExpression']);

/** Expressions that build a value out of others (not a call, whose result is something else). */
const CARRIER_INIT = new Set(['ObjectExpression', 'ArrayExpression', 'TemplateLiteral', 'BinaryExpression', 'LogicalExpression', 'ConditionalExpression']);

const describePath = (t: Taint): string => (t.kind === 'file' && t.resolved && t.resolved !== '…' ? ` (${t.resolved})` : '');

/**
 * Add what value-following finds (js-flow.ts) to the name-matched results:
 * where each file flow's path leads, flows the name match missed, credential
 * reads through built paths, and calls into the skill's helper modules.
 */
function mergeFlows(ast: JsAst, results: DataFlowResult[], lineText: (line: number) => string): void {
  let fa: ReturnType<typeof analyzeFlows>;
  try {
    fa = analyzeFlows(ast);
  } catch {
    return;
  }
  const byLine = new Map<number, typeof fa.flows>();
  for (const f of fa.flows) byLine.set(f.line, [...(byLine.get(f.line) ?? []), f]);
  const pathFields = (t: Taint | undefined): Pick<DataFlowResult, 'sourcePath' | 'resolvedPath'> =>
    t?.kind === 'file' && t.path ? { sourcePath: t.path, ...(t.resolved ? { resolvedPath: t.resolved } : {}) } : {};

  const covered = new Set<number>();
  for (const r of results) {
    if (r.type !== 'source-to-sink') continue;
    covered.add(r.line);
    if (r.sourceKind !== 'file') continue;
    const same = byLine.get(r.line)?.find(f => f.taint.kind === 'file' && (f.source === r.source || !fa.namedReads.has(r.source ?? '')));
    Object.assign(r, pathFields(same?.taint ?? fa.namedReads.get(r.source ?? '')));
  }
  const added = new Set<string>();
  for (const f of fa.flows) {
    if (covered.has(f.line)) continue;
    // one flow per value, sink and line: an object carrying two values of one source is one flow
    const key = `${f.line}\0${f.source}\0${f.sink}`;
    if (added.has(key)) continue;
    added.add(key);
    const t = f.taint;
    const kind = t.kind === 'file' ? 'file' : 'env';
    const what = t.kind === 'host' ? (f.source === t.origin ? '' : ` (${t.origin})`) : describePath(t);
    results.push({
      type: 'source-to-sink',
      source: f.source,
      sourceKind: kind,
      ...(t.kind === 'env' && t.wholeEnv ? { wholeEnv: true } : {}),
      ...pathFields(t),
      sink: f.sink,
      ...(f.sinkObject ? { sinkObject: f.sinkObject } : {}),
      derived: true,
      ...(f.dns ? { dns: true } : {}),
      line: f.line,
      ...cutLine(lineText(f.line)),
      description: f.via
        ? `Data flows from "${f.source}"${what} through ${f.via}() to ${f.sink}`
        : f.dns
          ? `Data flows from "${f.source}"${what} into a DNS query name (${f.sink})`
          : `Data flows from "${f.source}"${what} to ${/(?:^|\.|\()fetch\)?$/.test(f.sink) ? `${f.sink}()` : `network sink "${f.sink}"`}`,
    });
  }
  const reported = new Set(results.filter(r => r.type === 'fs-access').map(r => r.line));
  for (const c of fa.credentialReads) {
    if (reported.has(c.line)) continue;
    results.push({ type: 'fs-access', source: c.resolved, line: c.line, ...cutLine(lineText(c.line)), description: `Reading sensitive path: ${c.resolved}` });
  }
  for (const m of fa.moduleCalls) {
    const t = m.taint;
    results.push({
      type: 'module-call', source: m.source, sourceKind: t.kind === 'file' ? 'file' : 'env',
      ...(t.kind === 'env' && t.wholeEnv ? { wholeEnv: true } : {}), ...pathFields(t),
      module: m.module, exportName: m.exportName, argIndex: m.argIndex,
      line: m.line, ...cutLine(lineText(m.line)),
      description: `Data from "${m.source}"${describePath(t)} passed to ${m.module}`,
    });
  }
  for (const p of fa.paramSinks) {
    results.push({
      type: 'param-sink', exportName: p.exportName, argIndex: p.paramIndex, sink: p.sink,
      line: p.line, ...cutLine(lineText(p.line)),
      description: `Parameter ${p.paramIndex + 1} of export "${p.exportName}" reaches ${p.sink}`,
    });
  }
}

type ArgNode = Node | { type: string };

/**
 * Static text of a command/code argument list: string literals and template
 * quasis as written, `${…}` for interpolations, array elements (spawn argv)
 * joined with spaces. Flags computed values and runtime decoding.
 */
/** child_process calls that start a program without a shell (unless `shell: true`). */
const DIRECT_EXEC_FUNCTIONS = new Set(['execFile', 'execFileSync', 'spawn', 'spawnSync']);
const SHELL_OR_INTERPRETER = /^(?:.*\/)?(?:sh|bash|zsh|dash|ksh|fish|cmd(?:\.exe)?|powershell(?:\.exe)?|pwsh|node|deno|bun|python[\d.]*|perl|ruby|php|osascript)$/i;

/**
 * A program started directly — `execFileSync('git', [...])`, `spawn('ffmpeg', args)`:
 * every value the program can take is fixed (`programValues`) and none is a
 * shell or an interpreter (which would run code given as an argument), and no
 * `shell: true` option. What it runs is a known program with runtime
 * arguments, not code built at runtime (same rule as the Python analyzer's
 * subprocess without shell=True).
 */
function runsDirectly(name: string, call: NodePath, constStrings: ReadonlyMap<string, string>): boolean {
  if (!DIRECT_EXEC_FUNCTIONS.has(name.slice(name.lastIndexOf('.') + 1))) return false;
  const args = call.get('arguments') as NodePath[];
  const program = args[0];
  if (!program) return false;
  const values = programValues(program, constStrings);
  if (!values || values.length === 0 || values.some((v) => !v.trim() || SHELL_OR_INTERPRETER.test(v.trim()))) return false;
  return !args.some(a => {
    const n = a.node;
    return n.type === 'ObjectExpression' && n.properties.some(p =>
      p.type === 'ObjectProperty'
      && ((p.key.type === 'Identifier' && p.key.name === 'shell') || (p.key.type === 'StringLiteral' && p.key.value === 'shell'))
      && !(p.value.type === 'BooleanLiteral' && !p.value.value));
  });
}

/** How far `programValues` follows bindings, returns and properties. */
const MAX_RESOLVE_DEPTH = 8;

/**
 * Every value an expression naming a program can take, when each is fixed:
 * a literal or string constant, both sides of `cond ? 'a' : 'b'` and
 * `a || 'b'`, each element of a constant list it is drawn from
 * (`for (const curl of win ? ['curl.exe', 'curl'] : ['curl'])`, `LIST[i]`),
 * and a property of a constant object or of every object a local function
 * returns (`resolveCommand().file`, `const c = resolve(); c.file`).
 * `process.execPath` is the Node binary. Undefined when any value is
 * computed at runtime or comes from a parameter.
 */
function programValues(path: NodePath, constStrings: ReadonlyMap<string, string>, depth = 0): string[] | undefined {
  if (depth > MAX_RESOLVE_DEPTH) return undefined;
  const n = path.node;
  const next = (p: NodePath): string[] | undefined => programValues(p, constStrings, depth + 1);
  switch (n.type) {
    case 'StringLiteral':
      return [n.value];
    case 'TemplateLiteral':
      return n.expressions.length === 0 ? [n.quasis[0]?.value.cooked ?? ''] : undefined;
    case 'ConditionalExpression':
      return union(next(path.get('consequent') as NodePath), next(path.get('alternate') as NodePath));
    case 'LogicalExpression':
      return n.operator === '&&' ? undefined : union(next(path.get('left') as NodePath), next(path.get('right') as NodePath));
    case 'AwaitExpression':
    case 'TSAsExpression':
    case 'TSNonNullExpression':
    case 'ParenthesizedExpression':
      return next(path.get('expression' in n ? 'expression' : 'argument') as NodePath);
    case 'Identifier': {
      const binding = path.scope.getBinding(n.name);
      if (!binding) return constStrings.has(n.name) ? [constStrings.get(n.name)!] : undefined;
      if (!binding.constant || !binding.path.isVariableDeclarator()) return undefined;
      const decl = binding.path;
      // `for (const x of LIST)`: x is one of LIST's elements
      const loop = decl.parentPath?.parentPath;
      if (loop?.isForOfStatement() && decl.parentPath?.key === 'left') return listValues(loop.get('right'), constStrings, depth + 1);
      if (decl.node.id.type !== 'Identifier' || !decl.node.init) return undefined;
      return next(decl.get('init') as NodePath);
    }
    case 'MemberExpression': {
      const object = path.get('object') as NodePath;
      if (!n.computed && n.object.type === 'Identifier' && n.object.name === 'process'
        && n.property.type === 'Identifier' && n.property.name === 'execPath' && !path.scope.getBinding('process')) return ['node'];
      // LIST[i]: one of the list's elements
      if (n.computed && n.property.type !== 'StringLiteral') return listValues(object, constStrings, depth + 1);
      const key = n.property.type === 'Identifier' && !n.computed ? n.property.name
        : n.property.type === 'StringLiteral' ? n.property.value : undefined;
      if (key === undefined) return undefined;
      const objects = objectValues(object, depth + 1);
      if (!objects || objects.length === 0) return undefined;
      let out: string[] | undefined = [];
      for (const o of objects) {
        const prop = (o.get('properties') as NodePath[]).find((p) => {
          if (!p.isObjectProperty() || p.node.computed) return false;
          const k = p.node.key;
          return (k.type === 'Identifier' && k.name === key) || (k.type === 'StringLiteral' && k.value === key);
        });
        if (!prop) return undefined; // spread or missing: not every value is known
        out = union(out, next(prop.get('value') as NodePath));
      }
      return out;
    }
    default:
      return undefined;
  }
}

function union(a: string[] | undefined, b: string[] | undefined): string[] | undefined {
  return a && b ? [...a, ...b] : undefined;
}

/** Every element of a constant list (spreads of constant lists included). */
function listValues(path: NodePath, constStrings: ReadonlyMap<string, string>, depth: number): string[] | undefined {
  if (depth > MAX_RESOLVE_DEPTH) return undefined;
  const n = path.node;
  if (n.type === 'ArrayExpression') {
    let out: string[] | undefined = [];
    for (const el of path.get('elements') as NodePath[]) {
      if (!el.node) return undefined;
      out = union(out, el.isSpreadElement() ? listValues(el.get('argument'), constStrings, depth + 1) : programValues(el, constStrings, depth + 1));
    }
    return out;
  }
  if (n.type === 'ConditionalExpression') {
    return union(listValues(path.get('consequent') as NodePath, constStrings, depth + 1), listValues(path.get('alternate') as NodePath, constStrings, depth + 1));
  }
  if (n.type === 'Identifier') {
    const binding = path.scope.getBinding(n.name);
    if (!binding?.constant || !binding.path.isVariableDeclarator() || !binding.path.node.init) return undefined;
    return listValues(binding.path.get('init') as NodePath, constStrings, depth + 1);
  }
  return undefined;
}

/**
 * The object literals an expression can be: a constant bound to one, or
 * what a local function returns on every path (`function f() { return {…} }`,
 * `const f = () => ({…})`, awaited or not).
 */
function objectValues(path: NodePath, depth: number): Array<NodePath<import('@babel/types').ObjectExpression>> | undefined {
  if (depth > MAX_RESOLVE_DEPTH) return undefined;
  if (path.isObjectExpression()) return [path];
  if (path.isAwaitExpression()) return objectValues(path.get('argument'), depth + 1);
  if (path.isConditionalExpression()) {
    const [c, alt] = [path.get('consequent'), path.get('alternate')];
    if (isNothing(c)) return objectValues(alt, depth + 1);
    if (isNothing(alt)) return objectValues(c, depth + 1);
    const a = objectValues(c, depth + 1);
    const b = objectValues(alt, depth + 1);
    return a && b ? [...a, ...b] : undefined;
  }
  if (path.isIdentifier()) {
    const binding = path.scope.getBinding(path.node.name);
    if (!binding?.constant || !binding.path.isVariableDeclarator() || !binding.path.node.init) return undefined;
    return objectValues(binding.path.get('init') as NodePath, depth + 1);
  }
  if (path.isCallExpression()) {
    const callee = path.get('callee');
    if (!callee.isIdentifier()) return undefined;
    const binding = callee.scope.getBinding(callee.node.name);
    if (!binding?.constant) return undefined;
    let fn: NodePath | undefined = binding.path;
    if (fn.isVariableDeclarator()) fn = fn.node.init ? (fn.get('init') as NodePath) : undefined;
    if (!fn || !(fn.isFunctionDeclaration() || fn.isFunctionExpression() || fn.isArrowFunctionExpression())) return undefined;
    const body = fn.get('body') as NodePath;
    if (!body.isBlockStatement()) return objectValues(body, depth + 1);
    const returns: NodePath[] = [];
    body.traverse({
      Function(inner) { inner.skip(); },
      ReturnStatement(ret) { returns.push(ret.get('argument') as NodePath); },
    });
    const out: Array<NodePath<import('@babel/types').ObjectExpression>> = [];
    for (const r of returns) {
      // `return null` / `return;`: no object, so no program is read from it
      // (the caller checks — `if (!launcher) return`); every other return counts
      if (!r.node || isNothing(r)) continue;
      const objs = objectValues(r, depth + 1);
      if (!objs) return undefined;
      out.push(...objs);
    }
    return out.length > 0 ? out : undefined;
  }
  return undefined;
}

/** `null`, `undefined` or `void 0`: a value with no properties. */
function isNothing(path: NodePath): boolean {
  return path.isNullLiteral() || (path.isIdentifier() && path.node.name === 'undefined')
    || (path.isUnaryExpression() && path.node.operator === 'void');
}

function commandText(args: ArgNode[]): Pick<DataFlowResult, 'command' | 'dynamic' | 'decoded'> {
  let dynamic = false;
  let decoded = false;
  const text = (node: ArgNode | null | undefined, depth = 0): string => {
    if (!node || depth > 6) return '';
    const n = node as Node;
    switch (n.type) {
      case 'StringLiteral':
        return n.value;
      case 'TemplateLiteral':
        return n.quasis.map((q, i) => (q.value.cooked ?? '') + (i < n.expressions.length ? (dynamic = true, '${…}') : '')).join('');
      case 'ArrayExpression':
        return n.elements.map((e) => text(e as ArgNode, depth + 1)).join(' ');
      case 'BinaryExpression':
        return n.operator === '+' ? text(n.left, depth + 1) + text(n.right, depth + 1) : ((dynamic = true), '');
      case 'CallExpression': {
        const src = calleeText(n.callee);
        const bufferToString = src === '.toString' && n.callee.type === 'MemberExpression' &&
          n.callee.object.type === 'CallExpression' && calleeText(n.callee.object.callee) === 'Buffer.from';
        if (bufferToString || /^(?:atob|String\.fromCharCode|unescape)$/.test(src)) decoded = true;
        if (n.callee.type === 'MemberExpression' && n.callee.object.type === 'CallExpression') text(n.callee.object, depth + 1);
        dynamic = true;
        return '${…}';
      }
      case 'ObjectExpression':
        return ''; // spawn/exec options
      default:
        dynamic = true;
        return '${…}';
    }
  };
  const command = args.slice(0, 2).map((a) => text(a)).filter(Boolean).join(' ').trim();
  return { ...(command && command !== '${…}' ? { command } : {}), ...(dynamic ? { dynamic } : {}), ...(decoded ? { decoded } : {}) };
}

function memberIs(m: Node, name: string): boolean {
  return memberName(m) === name;
}

function calleeText(callee: Node): string {
  if (callee.type === 'Identifier') return callee.name;
  if (callee.type === 'MemberExpression' && callee.property.type === 'Identifier') {
    const obj = callee.object.type === 'Identifier' ? callee.object.name : '';
    return obj ? `${obj}.${callee.property.name}` : `.${callee.property.name}`;
  }
  return '';
}
