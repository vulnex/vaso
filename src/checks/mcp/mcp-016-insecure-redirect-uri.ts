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
const BOUND_FROM_REQUEST = new RegExp(String.raw`\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*` + REQUEST_VALUE, 'g');
const DESTRUCTURED_FROM_REQUEST = /\b(?:const|let|var)\s*\{([^{}]*)\}\s*=\s*(?:req|request)\.(?:query|params|body)\b/g;

/**
 * Names bound straight from the request (`const r = req.query.redirect_uri`,
 * `const { next } = req.query`, `const to = url.searchParams.get("to")`) that
 * nothing checks: a name compared, looked up in an allowlist or passed to a
 * validator is the server choosing which targets it accepts.
 */
function requestBoundNames(code: string): string[] {
  const names = new Set<string>();
  for (const m of code.matchAll(BOUND_FROM_REQUEST)) names.add(m[1]);
  for (const m of code.matchAll(DESTRUCTURED_FROM_REQUEST)) {
    for (const part of m[1].split(',')) {
      const local = /^\s*(?:[\w$]+\s*:\s*)?([A-Za-z_$][\w$]*)\s*(?:=.*)?$/.exec(part)?.[1];
      if (local) names.add(local);
    }
  }
  return [...names].filter((n) => {
    const name = n.replace(/\$/g, '\\$');
    const checked = new RegExp(String.raw`(?:\.(?:includes|has|indexOf|test)\s*\(\s*${name}(?![\w$])|(?<![\w$.])${name}\s*(?:[!=]==?)|[!=]==?\s*${name}(?![\w$])|(?<![\w$.])${name}\??\.(?:startsWith|match)\s*\(|\w*(?:valid|allow|whitelist|safe|trusted)\w*\s*\(\s*${name}(?![\w$]))`, 'i');
    return !checked.test(code);
  });
}

/** A redirect or Location header whose target starts with one of `names`. */
function boundRedirectPatterns(names: string[]): Array<{ pattern: RegExp; detail: string }> {
  if (names.length === 0) return [];
  const alt = names.map((n) => n.replace(/\$/g, '\\$')).join('|');
  const start = String.raw`\`?(?:\$\{\s*)?(?:${alt})(?![\w$])`;
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
      const patterns = [...SOURCE_REDIRECT_PATTERNS, ...boundRedirectPatterns(requestBoundNames(source.sourceCode))];

      for (let i = 0; i < segments.length; i++) {
        const line = segments[i].text;

        // Skip comment lines
        if (line.trim().startsWith('//') || line.trim().startsWith('*')) continue;

        for (const { pattern, detail } of patterns) {
          if (pattern.test(line)) {
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
