import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { sourceSegments } from '../../mcp/source-segments.js';
import { sourceSnippet } from '../../mcp/source-snippet.js';

const LOCALHOST_EXCEPTIONS = ['localhost', '127.0.0.1', '[::1]'];

function isLocalhostUrl(url: string): boolean {
  return LOCALHOST_EXCEPTIONS.some(host => url.includes(host));
}

const SOURCE_REDIRECT_PATTERNS = [
  { pattern: /redirect_uri['":\s]*['"]?http:\/\/(?!localhost|127\.0\.0\.1|\[::1\])/, detail: 'HTTP redirect_uri (must use HTTPS for OAuth 2.1)' },
  { pattern: /redirect_uri['":\s]*['"]?\*/, detail: 'Wildcard redirect_uri pattern — allows open redirect attacks' },
  // A redirect allowlist set to everything: `allowedRedirect: "*"`, `redirectUris: ["*"]`, `ALLOWED_REDIRECTS = ["*"]`
  { pattern: /\b\w*redirect\w*["']?\s*[:=]\s*\[?\s*(["'`])\*\1/i, detail: 'Wildcard redirect allowlist — any redirect target is accepted (open redirect)' },
  { pattern: /redirect_uri['":\s]*['"`][^'"`]*\.\.[\/\\]/, detail: 'Path traversal in redirect_uri' },
  // An open redirect needs a redirect *sink* fed by the request. Reading
  // `redirect_uri` from a token request to pass on for verification is the
  // protocol, not a redirect.
  { pattern: /\.redirect\s*\(\s*(?:\d{3}\s*,\s*)?(?:(?:req|request)\.(?:query|params|body)\b|(?:\w+\.)?(?:searchParams|params|query)\.get\s*\()/, detail: 'User-controlled redirect target — potential open redirect' },
  { pattern: /\bLocation["']?\s*:\s*(?:(?:req|request)\.(?:query|params|body)\b|(?:\w+\.)?(?:searchParams|params|query)\.get\s*\()/, detail: 'User-controlled Location header — potential open redirect' },
];

/** Where a request value comes from, as the redirect patterns above read it. */
const REQUEST_VALUE = String.raw`(?:(?:req|request)\.(?:query|params|body)\b|(?:\w+\.)?(?:searchParams|params|query)\.get\s*\()`;
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

/**
 * Whether `region` (from the name's binding to its redirect) checks the
 * name: compares it to something (not to nothing), looks it up in an
 * allowlist, tests its prefix, or passes it to a validator (`isAllowed(r)`,
 * `validateRedirect(client, r)`, `checkRedirect(r)`, `ensureSafe(r)`). A
 * URL parsed from it (`const u = new URL(r, base)`) counts when its parts are
 * compared (`u.origin !== ORIGIN`).
 */
function checkedIn(name: string, region: string): boolean {
  const names = [escapeName(name)];
  const parsed = new RegExp(String.raw`\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:new\s+URL|URL\.parse|(?:url\.)?parse)\s*\(\s*${names[0]}(?![\w$])`, 'g');
  for (const m of region.matchAll(parsed)) names.push(String.raw`${escapeName(m[1])}(?:\.(?:origin|host|hostname|href|protocol))?`);
  return names.some((n) => new RegExp(String.raw`(?:\.(?:includes|has|indexOf|test)\s*\(\s*${n}(?![\w$])|(?<![\w$.])(?=${n})(?<!typeof\s+)${n}\s*[!=]==?(?!=)\s*(?!\s|${NOTHING})|(?=[!=]=)(?<![=!])(?<!${NOTHING}\s*)[!=]==?\s*${n}(?![\w$])|(?<![\w$.])${n}\??\.(?:startsWith|match)\s*\(|\w*(?:valid|allow|whitelist|safe|trusted|check|ensure|verify|assert)\w*\s*\([^()]*?(?<![\w$.])${n}(?![\w$]))`, 'i').test(region));
}

/** A redirect or Location header whose target starts with one of `names` (group 1: the name). */
function boundRedirectPatterns(names: string[]): Array<{ pattern: RegExp; detail: string }> {
  if (names.length === 0) return [];
  const alt = names.map(escapeName).join('|');
  const start = String.raw`\`?(?:\$\{\s*)?(${alt})(?![\w$])`;
  return [
    { pattern: new RegExp(String.raw`\.redirect\s*\(\s*(?:\d{3}\s*,\s*)?` + start), detail: 'User-controlled redirect target (bound from the request) — potential open redirect' },
    { pattern: new RegExp(String.raw`\bLocation["']?\s*[:,]\s*` + start), detail: 'User-controlled Location header (bound from the request) — potential open redirect' },
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
            let binding: RequestBinding | undefined;
            for (const b of bindings) if (b.name === m[1] && b.end <= lineEnd) binding = b;
            if (!binding || checkedIn(m[1], code.slice(binding.end, lineEnd))) continue;
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
