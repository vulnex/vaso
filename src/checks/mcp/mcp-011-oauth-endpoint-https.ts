import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

const OAUTH_URL_ENV_PATTERNS = /(?:oauth|auth|token|authorize)[_-]?(?:url|endpoint|uri|server)/i;

const LOCALHOST_EXCEPTIONS = ['localhost', '127.0.0.1', '[::1]'];

function isLocalhostUrl(url: string): boolean {
  return LOCALHOST_EXCEPTIONS.some(host => url.includes(host));
}

const SOURCE_HTTP_OAUTH_PATTERNS = [
  { pattern: /authorization_endpoint['":\s]*['"]?http:\/\/(?!localhost|127\.0\.0\.1|\[::1\])/, detail: 'HTTP authorization_endpoint URL' },
  { pattern: /token_endpoint['":\s]*['"]?http:\/\/(?!localhost|127\.0\.0\.1|\[::1\])/, detail: 'HTTP token_endpoint URL' },
  { pattern: /\.well-known\/oauth-authorization-server.*http:\/\/(?!localhost|127\.0\.0\.1|\[::1\])/, detail: 'HTTP OAuth discovery endpoint' },
  { pattern: /http:\/\/(?!localhost|127\.0\.0\.1|\[::1\])[^'"\s]*\/authorize/, detail: 'HTTP authorization URL' },
  { pattern: /http:\/\/(?!localhost|127\.0\.0\.1|\[::1\])[^'"\s]*\/oauth\/token/, detail: 'HTTP OAuth token URL' },
  { pattern: /http:\/\/(?!localhost|127\.0\.0\.1|\[::1\])[^'"\s]*\/oauth2\//, detail: 'HTTP OAuth2 endpoint URL' },
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
          if (OAUTH_URL_ENV_PATTERNS.test(key) && value.startsWith('http://') && !isLocalhostUrl(value)) {
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
      const lines = source.sourceCode.split('\n');

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        for (const { pattern, detail } of SOURCE_HTTP_OAUTH_PATTERNS) {
          if (pattern.test(line)) {
            evidence.push({
              file: source.localPath ?? source.serverName,
              line: i + 1,
              snippet: line.trim(),
              detail,
            });
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
