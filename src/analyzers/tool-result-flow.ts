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
 * an HTTP request (requests, httpx, aiohttp, urllib) and returns a value.
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

/** The first piece of a URL expression: a literal prefix, or the parameter it starts with. */
function leftmost(path: NodePath, depth: number): { literal?: string; param?: string } | undefined {
  if (depth > 4 || !path.node) return undefined;
  if (path.isStringLiteral()) return { literal: path.node.value };
  if (path.isTemplateLiteral()) {
    const first = path.node.quasis[0]?.value.cooked ?? '';
    if (first) return { literal: first };
    const expr = (path.get('expressions') as NodePath[])[0];
    return expr ? leftmost(expr, depth + 1) : undefined;
  }
  if (path.isBinaryExpression() && path.node.operator === '+') return leftmost(path.get('left') as NodePath, depth + 1);
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
  if (binding.kind === 'param') return { param: path.node.name };
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

// ── Python ─────────────────────────────────────────────────────────────

const PY_TOOL_DECORATOR = /^\s*@\s*[\w.]+\.(?:tool|call_tool)\s*\(/;
const PY_HTTP_CALL = /\b(?:requests|httpx|client|session|http|aiohttp|urllib\.request)\s*\.\s*(?:get|post|request|stream|urlopen)\s*\(|\burlopen\s*\(/;

function analyzePython(code: string): ExternalContentFlow[] {
  const lines = code.split('\n');
  const results: ExternalContentFlow[] = [];
  for (let i = 0; i < lines.length; i++) {
    if (!PY_TOOL_DECORATOR.test(lines[i])) continue;
    // The decorated def, then its indented body.
    let def = i + 1;
    while (def < lines.length && /^\s*@/.test(lines[def])) def++;
    const header = /^(\s*)(?:async\s+)?def\s+\w+\s*\(([^)]*)\)/.exec(lines[def] ?? '');
    if (!header) continue;
    const indent = header[1].length;
    const params = header[2].split(',').map((p) => p.split(/[:=]/)[0].trim()).filter((p) => p && p !== 'self');
    let returns = false;
    let call: { line: number; text: string } | undefined;
    for (let j = def + 1; j < lines.length; j++) {
      const text = lines[j];
      if (text.trim() !== '' && text.search(/\S/) <= indent && !/^\s*#/.test(text)) break;
      if (!call && PY_HTTP_CALL.test(text)) call = { line: j + 1, text };
      // A value, not just a literal message (`return "Not found."`).
      if (/^\s*return\s+\S/.test(text) && !/^\s*return\s+(?:f?["'][^"'{]*["']|None|True|False|\d+)\s*$/.test(text)) returns = true;
    }
    if (!call || !returns) continue;
    // The URL: the call's first argument, possibly on the next line.
    const after = call.text.slice(call.text.search(PY_HTTP_CALL)).replace(/^[^(]*\(/, '') + ' ' + (lines[call.line] ?? '');
    const literal = /^\s*f?["']([^"']*)["']/.exec(after)?.[1];
    const firstName = /^\s*([A-Za-z_]\w*)\b/.exec(after)?.[1];
    const host = literal ? hostOf(literal) : undefined;
    results.push({
      line: call.line,
      snippet: call.text.trim().slice(0, 120),
      via: 'http',
      source: /\b(requests|httpx|aiohttp|urllib|client|session)\b/.exec(call.text)?.[1] ?? 'http',
      callerChosenUrl: !literal && firstName !== undefined && params.includes(firstName),
      openContentHost: host ? isOpenContentHost(host) : false,
      ...(host ? { host } : {}),
    });
  }
  return results;
}
