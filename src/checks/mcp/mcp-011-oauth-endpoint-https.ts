import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { sourceSegments } from '../../mcp/source-segments.js';
import { isRemotePlaintextUrl } from '../../mcp/remote-endpoint.js';
import { sourceSnippet } from '../../mcp/source-snippet.js';
import { foldConstants, referencedConstants, stringConstants } from '../../mcp/source-constants.js';

const OAUTH_URL_ENV_PATTERNS = /(?:oauth|auth|token|authorize)[_-]?(?:url|endpoint|uri|server)/i;

/**
 * `http://` followed by a host that is not loopback. The exemption is anchored
 * to the whole host (`http://localhost.attacker.example` is remote) and the
 * scheme matched in any case (`HTTP://`).
 */
const REMOTE_HTTP = String.raw`[hH][tT][tT][pP]:\/\/(?!(?:localhost|127(?:\.\d{1,3}){3}|\[::1\])(?:[:/'"\x60\s]|$))`;

const REMOTE_HTTP_URL = new RegExp('^' + REMOTE_HTTP);
/** A bare plaintext scheme constant (`const SCHEME = "http"`), folded into `${SCHEME}://host/…`. */
const PLAINTEXT_SCHEME = /^http(?::\/\/)?$/i;

/**
 * Whether the URL `pattern` finds in the folded line is only an operand of a
 * comparison or prefix test (`url.startsWith(HTTP_BASE + "/authorize")`,
 * `u === HTTP_BASE + "/authorize"`) — a URL the code checks for, typically to
 * reject it, not an endpoint it uses.
 */
function comparedOnly(folded: string, pattern: RegExp): boolean {
  const m = pattern.exec(folded);
  if (!m) return false;
  // the string literal holding the match
  const open = Math.max(folded.lastIndexOf('"', m.index), folded.lastIndexOf("'", m.index), folded.lastIndexOf('`', m.index));
  if (open === -1) return false;
  const close = folded.slice(open + 1).search(/["'`]/);
  const before = folded.slice(0, open);
  const after = close === -1 ? '' : folded.slice(open + 2 + close);
  return /(?:[!=]==?|\.(?:startsWith|endsWith|includes|indexOf|match|test|startswith|endswith)\s*\()\s*\(?\s*$/.test(before)
    || /^\s*\)?\s*[!=]==?/.test(after)
    || /\b(?:not\s+)?in\s*$/.test(before);
}

const SOURCE_HTTP_OAUTH_PATTERNS = [
  { pattern: new RegExp(String.raw`authorization_endpoint['":\s]*['"]?` + REMOTE_HTTP), detail: 'HTTP authorization_endpoint URL' },
  { pattern: new RegExp(String.raw`token_endpoint['":\s]*['"]?` + REMOTE_HTTP), detail: 'HTTP token_endpoint URL' },
  { pattern: new RegExp(String.raw`\.well-known\/oauth-authorization-server.*` + REMOTE_HTTP), detail: 'HTTP OAuth discovery endpoint' },
  { pattern: new RegExp(REMOTE_HTTP + String.raw`[^'"\s]*\/authorize`), detail: 'HTTP authorization URL' },
  { pattern: new RegExp(REMOTE_HTTP + String.raw`[^'"\s]*\/oauth\/token`), detail: 'HTTP OAuth token URL' },
  { pattern: new RegExp(REMOTE_HTTP + String.raw`[^'"\s]*\/oauth2\/`), detail: 'HTTP OAuth2 endpoint URL' },
];

export const mcp011 = defineCheck({
  id: 'MCP-011',
  name: 'OAuth Endpoint HTTPS',
  category: 'mcp',
  severity: 'critical',
  description: 'Check for OAuth authorization/token endpoints using HTTP instead of HTTPS (OAuth 2.1 mandates TLS)',
  supportedAgents: ['mcp'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    const mcpConfigs = ctx.mcpConfigs ?? [];
    const mcpServerSources = ctx.mcpServerSources ?? [];

    // Config scan: check env vars for HTTP OAuth endpoint URLs
    for (const config of mcpConfigs) {
      for (const server of config.servers) {
        if (!server.env) continue;

        for (const [key, value] of Object.entries(server.env)) {
          if (OAUTH_URL_ENV_PATTERNS.test(key) && isRemotePlaintextUrl(value)) {
            evidence.push({
              file: config.filePath,
              snippet: `Server "${server.name}": ${key}=${value}`,
              detail: `OAuth endpoint using HTTP — OAuth 2.1 mandates HTTPS for all endpoints`,
            });
          }
        }
      }
    }

    // Source scan: check for HTTP OAuth URLs in code
    for (const source of mcpServerSources) {
      if (!source.sourceCode) continue;
      const python = source.language === 'python';
      const segments = sourceSegments(source.sourceCode, { python });
      // A plaintext base URL held in a constant and joined with an OAuth path
      // where it is used (`AUTH_HOST + "/authorize"`, `new URL("/oauth/token", AUTH_HOST)`)
      const constants = stringConstants(source.sourceCode, { python });
      const remoteConstant = [...constants.values.values()].some((v) => REMOTE_HTTP_URL.test(v) || PLAINTEXT_SCHEME.test(v));

      for (let i = 0; i < segments.length; i++) {
        const line = segments[i].text;
        const folded = remoteConstant ? foldConstants(line, constants) : undefined;
        // A constant that is an OAuth endpoint by itself is reported at its
        // binding; a line only using it (`fetch(TOKEN_URL)`, logging it) adds
        // nothing — one built from it (`AUTH_HOST + "/authorize"`) does
        const used = folded !== undefined ? referencedConstants(line, constants).map((v) => `"${v}"`) : [];
        for (const { pattern, detail } of SOURCE_HTTP_OAUTH_PATTERNS) {
          const direct = pattern.test(line);
          if (direct || (folded !== undefined && pattern.test(folded) && !used.some((v) => pattern.test(v)) && !comparedOnly(folded, pattern))) {
            evidence.push({
              file: source.localPath ?? source.serverName,
              line: segments[i].line,
              snippet: sourceSnippet(source, line),
              detail: direct ? detail : `${detail} (built from a same-file string constant)`,
            });
            break; // one finding per line: the patterns overlap on one URL
          }
        }
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'All OAuth endpoints use HTTPS',
      failed: (n) => `Found ${n} OAuth endpoint(s) using HTTP instead of HTTPS`,
      fixable: evidence.length > 0,
      fixDescription: 'Change all OAuth endpoint URLs from http:// to https://',
    });
  },
});
