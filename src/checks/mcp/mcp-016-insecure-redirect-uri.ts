import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { sourceSegments } from '../../mcp/source-segments.js';
import { sourceSnippet } from '../../mcp/source-snippet.js';

const LOCALHOST_EXCEPTIONS = ['localhost', '127.0.0.1', '[::1]'];

function isLocalhostUrl(url: string): boolean {
  return LOCALHOST_EXCEPTIONS.some(host => url.includes(host));
}

/**
 * Where a request value comes from: Express/Node (`req.query`, `params.get(`)
 * and Python frameworks (Flask `request.args`/`form`/`values`, Starlette
 * `request.query_params`/`path_params`, Django `request.GET`/`POST`).
 */
const REQUEST_SOURCE = String.raw`(?:(?:req|request)\.(?:query|params|body|args|form|values|query_params|path_params|GET|POST)\b|(?:\w+\.)?(?:searchParams|params|query)\.get\s*\()`;
/** Wrappers that pass the value through unchanged (`decodeURIComponent(…)`, `String(…)`, Python `unquote(…)`/`str(…)`). */
const PASS_THROUGH = String.raw`(?:(?:decodeURIComponent|decodeURI|String|unquote|unquote_plus|str)\s*\(\s*)*`;
/** A template or f-string whose first part is the value (`\`${req.query.next}\``, `f"{request.args['next']}"`). */
const TEMPLATE_START = String.raw`(?:\x60\$\{\s*|f["']\{\s*)?`;
/** Where a request value comes from, as the redirect patterns read it. */
const REQUEST_VALUE = PASS_THROUGH + REQUEST_SOURCE;
/**
 * Calls that send a redirect to their (first, or `url=`) argument: Express
 * `res.redirect()`/`res.location()`, Next.js/Flask/Remix `redirect()`,
 * Starlette/FastAPI `RedirectResponse()`, Django `HttpResponseRedirect()`.
 */
const REDIRECT_CALL = String.raw`(?:\.(?:redirect|location)|(?<![\w$.])redirect|\bRedirectResponse|\bHttpResponse(?:Permanent)?Redirect)\s*\(\s*(?:\d{3}\s*,\s*)?(?:url\s*=\s*)?`;
/** A Location header: `{ Location: x }`, `setHeader("Location", x)`, `headers["Location"] = x`. */
const LOCATION_HEADER = String.raw`\bLocation["']?(?:\s*\])?\s*(?:[:,]|=(?!=))\s*`;

const SOURCE_REDIRECT_PATTERNS = [
  { pattern: /redirect_uri['":\s]*['"]?http:\/\/(?!localhost|127\.0\.0\.1|\[::1\])/, detail: 'HTTP redirect_uri (must use HTTPS for OAuth 2.1)' },
  { pattern: /redirect_uri['":\s]*['"]?\*/, detail: 'Wildcard redirect_uri pattern — allows open redirect attacks' },
  { pattern: /\b\w*redirect\w*["']?\s*[:=]\s*\[?\s*(["'`])\*\1/i, detail: 'Wildcard redirect allowlist — any redirect target is accepted (open redirect)' },
  { pattern: /redirect_uri['":\s]*['"`][^'"`]*\.\.[\/\\]/, detail: 'Path traversal in redirect_uri' },
  { pattern: new RegExp(REDIRECT_CALL + TEMPLATE_START + REQUEST_VALUE), detail: 'User-controlled redirect target — potential open redirect' },
  { pattern: new RegExp(LOCATION_HEADER + TEMPLATE_START + REQUEST_VALUE), detail: 'User-controlled Location header — potential open redirect' },
];

/** `const r = req.query.x`, and a plain assignment to a name declared earlier (`let r; r = req.query.x`). */
const BOUND_FROM_REQUEST = new RegExp(String.raw`(?:\b(?:const|let|var)\s+|(?<![\w$.])(?=[A-Za-z_$][\w$]*\s*=[^=]))([A-Za-z_$][\w$]*)\s*=\s*` + REQUEST_VALUE, 'g');
const DESTRUCTURED_FROM_REQUEST = /\b(?:const|let|var)\s*\{([^{}]*)\}\s*=\s*(?:req|request)\.(?:query|params|body)\b/g;

/** A name bound straight from the request, and the offset just past its binding. */
interface RequestBinding { name: string; end: number }

/**
 * Names bound straight from the request (`const r = req.query.redirect_uri`,
 * `const { next } = req.query`, `const to = url.searchParams.get("to")`,
 * `let r; r = req.query.next`), in file order.
 */
function requestBindings(code: string): RequestBinding[] {
  const out: RequestBinding[] = [];
  for (const m of code.matchAll(BOUND_FROM_REQUEST)) out.push({ name: m[1], end: m.index + m[0].length });
  for (const m of code.matchAll(DESTRUCTURED_FROM_REQUEST)) {
    for (const part of m[1].split(',')) {
      const local = /^\s*(?:[\w$]+\s*:\s*)?([A-Za-z_$][\w$]*)\s*(?:=.*)?$/.exec(part)?.[1];
      if (local) out.push({ name: local, end: m.index + m[0].length });
    }
  }
  return out.sort((a, b) => a.end - b.end);
}

const escapeName = (n: string): string => n.replace(/\$/g, '\\$');
/** A comparison with nothing (`=== undefined`, `!= null`, `=== ""`): a presence test, not a check of the target. */
const NOTHING = String.raw`(?:null|undefined|""|''|\x60\x60)(?![\w$])`;

/** Validator names that only log or report the value (`logAllowed(r)`), not judge it. */
const NOT_A_VALIDATOR = /^(?:log|print|debug|trace|warn|info|emit|record|report|track|notify|send|console)/i;
const VALIDATOR_CALL = /([A-Za-z_$][\w$]*)\s*\(/g;

/**
 * Whether a positive equality test ending at `at` guards the redirect at the
 * end of `region`: the redirect sits inside the block it opens (an unclosed
 * `{`, or a deeper-indented Python suite) or in the same statement
 * (`if (r === "/") res.redirect(r)`). `if (r === "/") log(); res.redirect(r)`
 * is no check of what is redirected to.
 */
function guardsRedirect(region: string, at: number, python: boolean): boolean {
  const after = region.slice(at);
  if (python) {
    const lineStart = region.lastIndexOf('\n', at - 1) + 1;
    const indent = /^[ \t]*/.exec(region.slice(lineStart))![0].length;
    const rest = after.split('\n');
    if (rest.length === 1) return true;
    // every line after the test, up to the redirect's, sits in the test's suite
    return rest.slice(1).every((l) => !l.trim() || /^[ \t]*/.exec(l)![0].length > indent);
  }
  let depth = 0;
  for (const ch of after) {
    if (ch === '{') depth++;
    else if (ch === '}') depth = Math.max(0, depth - 1);
  }
  return depth > 0 || !/[;\n]/.test(after);
}

/**
 * Whether `region` (from the name's binding to its redirect) checks the
 * name: compares it to something (not to nothing), looks it up in an
 * allowlist, tests its prefix, or passes it to a validator (`isAllowed(r)`,
 * `validateRedirect(client, r)`, `checkRedirect(r)`, `ensureSafe(r)`). A
 * URL parsed from it (`const u = new URL(r, base)`) counts when its parts are
 * compared (`u.origin !== ORIGIN`). A positive equality (`r === "/"`) counts
 * only when it guards the redirect; a rejecting one (`r !== X`) always does.
 * A function that only logs the value (`logAllowed(r)`) is no validator.
 */
function checkedIn(name: string, region: string, python = false): boolean {
  const names = [escapeName(name)];
  const parsed = new RegExp(String.raw`\b(?:(?:const|let|var)\s+)?([A-Za-z_$][\w$]*)\s*=\s*(?:new\s+URL|URL\.parse|(?:url\.|urllib\.parse\.)?(?:parse|urlparse|urlsplit))\s*\(\s*${names[0]}(?![\w$])`, 'g');
  for (const m of region.matchAll(parsed)) names.push(String.raw`${escapeName(m[1])}(?:\.(?:origin|host|hostname|href|protocol|netloc|scheme))?`);
  for (const n of names) {
    if (new RegExp(String.raw`(?:\.(?:includes|has|indexOf|test)\s*\(\s*${n}(?![\w$])|(?<![\w$.])${n}\??\.(?:startsWith|startswith|match)\s*\(|(?<![\w$.])${n}\s+(?:not\s+)?in\s+[\w$.\[({])`, 'i').test(region)) return true;
    // rejecting comparisons, either side
    if (new RegExp(String.raw`(?<![\w$.])(?<!typeof\s+)${n}\s*!==?\s*(?!\s|${NOTHING})|(?<![=!<>])(?<!${NOTHING}\s*)!==?\s*${n}(?![\w$])`, 'i').test(region)) return true;
    // positive comparisons, either side, only when they guard the redirect
    const positive = new RegExp(String.raw`(?<![\w$.])(?<!typeof\s+)${n}\s*===?(?!=)\s*(?!\s|${NOTHING})[^\s)&|]*|(?<![=!<>])(?<!${NOTHING}\s*)===?\s*${n}(?![\w$])`, 'gi');
    for (const m of region.matchAll(positive)) if (guardsRedirect(region, m.index + m[0].length, python)) return true;
    // validators taking the name as an argument
    const arg = new RegExp(String.raw`^[^()]*?(?<![\w$.])${n}(?![\w$])`);
    for (const m of region.matchAll(VALIDATOR_CALL)) {
      const fn = m[1];
      if (!/valid|allow|whitelist|safe|trusted|check|ensure|verify|assert/i.test(fn) || NOT_A_VALIDATOR.test(fn)) continue;
      if (arg.test(region.slice(m.index + m[0].length, m.index + m[0].length + 400))) return true;
    }
  }
  return false;
}

/** A redirect or Location header whose target starts with one of `names` (group 1: the name). */
function boundRedirectPatterns(names: string[]): Array<{ pattern: RegExp; detail: string }> {
  if (names.length === 0) return [];
  const alt = names.map(escapeName).join('|');
  const start = TEMPLATE_START + PASS_THROUGH + String.raw`(${alt})(?![\w$])`;
  return [
    { pattern: new RegExp(REDIRECT_CALL + start), detail: 'User-controlled redirect target (bound from the request) — potential open redirect' },
    { pattern: new RegExp(LOCATION_HEADER + start), detail: 'User-controlled Location header (bound from the request) — potential open redirect' },
  ];
}

export const mcp016 = defineCheck({
  id: 'MCP-016',
  name: 'Insecure Redirect URI',
  category: 'mcp',
  severity: 'warning',
  description: 'Detect HTTP redirect URIs, wildcard patterns, and user-controlled redirect targets in OAuth flows',
  supportedAgents: ['mcp'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    const mcpConfigs = ctx.mcpConfigs ?? [];
    const mcpServerSources = ctx.mcpServerSources ?? [];

    // Config scan: check env vars for HTTP redirect/callback URLs
    for (const config of mcpConfigs) {
      for (const server of config.servers) {
        if (!server.env) continue;

        for (const [key, value] of Object.entries(server.env)) {
          if (/redirect|callback/i.test(key) && value.startsWith('http://') && !isLocalhostUrl(value)) {
            evidence.push({
              file: config.filePath,
              snippet: `Server "${server.name}": ${key}=${value}`,
              detail: 'HTTP redirect/callback URI in env block — must use HTTPS',
            });
          }
        }
      }
    }

    // Source scan: check for insecure redirect patterns in code
    for (const source of mcpServerSources) {
      if (!source.sourceCode) continue;
      const segments = sourceSegments(source.sourceCode, { python: source.language === 'python' });
      const filePath = source.localPath ?? source.serverName;
      const code = source.sourceCode;
      const bindings = requestBindings(code);
      const bound = boundRedirectPatterns([...new Set(bindings.map((b) => b.name))]);
      const patterns = [...SOURCE_REDIRECT_PATTERNS, ...bound];
      // where each source line ends, to scope a bound name's checks to its own handler
      const lineEnds: number[] = [];
      for (let at = code.indexOf('\n'); at !== -1; at = code.indexOf('\n', at + 1)) lineEnds.push(at);
      lineEnds.push(code.length);

      const lines = code.split('\n');
      for (let i = 0; i < segments.length; i++) {
        const line = segments[i].text;

        // Skip comment lines
        if (line.trim().startsWith('//') || line.trim().startsWith('*')) continue;

        for (const { pattern, detail } of patterns) {
          const m = pattern.exec(line);
          if (m && bound.some((b) => b.pattern === pattern)) {
            // The value's own binding (the nearest before this line) up to the
            // redirect: a check there is the handler choosing what it accepts;
            // one in another handler, or a presence test, is not
            const lineEnd = lineEnds[segments[i].line - 1] ?? code.length;
            // where the redirect starts, when the segment is found in its line
            const lineStart = segments[i].line > 1 ? lineEnds[segments[i].line - 2] + 1 : 0;
            const inLine = (lines[segments[i].line - 1] ?? '').indexOf(line);
            const redirectAt = inLine === -1 ? lineEnd : lineStart + inLine + m.index;
            let binding: RequestBinding | undefined;
            for (const b of bindings) if (b.name === m[1] && b.end <= redirectAt) binding = b;
            if (!binding || checkedIn(m[1], code.slice(binding.end, redirectAt), source.language === 'python')) continue;
          }
          if (m) {
            evidence.push({
              file: filePath,
              line: segments[i].line,
              snippet: sourceSnippet(source, line),
              detail,
            });
            break;
          }
        }
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'All OAuth redirect URIs are properly secured',
      failed: (n) => `Found ${n} insecure redirect URI pattern(s)`,
      fixable: evidence.length > 0,
      fixDescription: 'Use HTTPS redirect URIs with exact-match validation; never allow user-controlled redirects',
    });
  },
});
