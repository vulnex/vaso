import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { sourceSegments } from '../../mcp/source-segments.js';
import { isRemotePlaintextUrl } from '../../mcp/remote-endpoint.js';

const OAUTH_URL_ENV_PATTERNS = /(?:oauth|auth|token|authorize)[_-]?(?:url|endpoint|uri|server)/i;

/**
 * `http://` followed by a host that is not loopback. The exemption is anchored
 * to the whole host (`http://localhost.attacker.example` is remote) and the
 * scheme matched in any case (`HTTP://`).
 */
const REMOTE_HTTP = String.raw`[hH][tT][tT][pP]:\/\/(?!(?:localhost|127(?:\.\d{1,3}){3}|\[::1\])(?:[:/'"\x60\s]|$))`;

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
      const segments = sourceSegments(source.sourceCode, { python: source.language === 'python' });

      for (let i = 0; i < segments.length; i++) {
        const line = segments[i].text;
        for (const { pattern, detail } of SOURCE_HTTP_OAUTH_PATTERNS) {
          if (pattern.test(line)) {
            evidence.push({
              file: source.localPath ?? source.serverName,
              line: segments[i].line,
              snippet: line.trim().slice(0, 120),
              detail,
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
