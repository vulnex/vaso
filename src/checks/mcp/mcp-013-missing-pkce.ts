import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { AUTHORIZE_ROUTE } from '../../mcp/oauth-context.js';
import { sourceSegments, nearbyText } from '../../mcp/source-segments.js';

const AUTHORIZE_URL_PATTERN = /\/authorize|\/authorization/;
const CODE_CHALLENGE_PATTERN = /code_challenge/;
const CODE_VERIFIER_PATTERN = /code_verifier/;
const PLAIN_CHALLENGE_PATTERN = /code_challenge_method['":\s]*['"]?plain/i;
const TOKEN_EXCHANGE_PATTERN = /\/token|grant_type|authorization_code/;

const SEARCH_RADIUS = 15;

export const mcp013 = defineCheck({
  id: 'MCP-013',
  name: 'Missing PKCE',
  category: 'mcp',
  severity: 'critical',
  description: 'Detect OAuth authorization flows without PKCE (Proof Key for Code Exchange) protection',
  supportedAgents: ['mcp'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    const mcpServerSources = ctx.mcpServerSources ?? [];

    for (const source of mcpServerSources) {
      if (!source.sourceCode) continue;
      const segments = sourceSegments(source.sourceCode);
      const filePath = source.localPath ?? source.serverName;

      for (let i = 0; i < segments.length; i++) {
        const line = segments[i].text;

        const trimmed = line.trim();
        if (trimmed.startsWith('//') || trimmed.startsWith('*')) continue;

        // Detect OAuth authorize URL construction without PKCE
        // A route the server handles forwards the client's PKCE parameters.
        if (AUTHORIZE_URL_PATTERN.test(line) && !AUTHORIZE_ROUTE.test(line)) {
          const nearbyCode = nearbyText(segments, i, SEARCH_RADIUS);

          if (!CODE_CHALLENGE_PATTERN.test(nearbyCode)) {
            evidence.push({
              file: filePath,
              line: segments[i].line,
              snippet: line.trim().slice(0, 120),
              detail: 'OAuth authorization URL constructed without PKCE code_challenge parameter',
            });
          }
        }

        // Detect plain code_challenge_method (should be S256)
        if (PLAIN_CHALLENGE_PATTERN.test(line)) {
          evidence.push({
            file: filePath,
            line: segments[i].line,
            snippet: line.trim().slice(0, 120),
            detail: 'PKCE code_challenge_method set to "plain" — must use "S256" for security',
          });
        }

        // Detect token exchange without code_verifier
        if (TOKEN_EXCHANGE_PATTERN.test(line) && /grant_type.*authorization_code|authorization_code.*grant_type/.test(line)) {
          const nearbyCode = nearbyText(segments, i, SEARCH_RADIUS);

          if (!CODE_VERIFIER_PATTERN.test(nearbyCode)) {
            evidence.push({
              file: filePath,
              line: segments[i].line,
              snippet: line.trim().slice(0, 120),
              detail: 'Token exchange with authorization_code grant but no code_verifier — PKCE not enforced',
            });
          }
        }
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'OAuth flows properly implement PKCE',
      failed: (n) => `Found ${n} OAuth flow(s) without PKCE protection`,
      fixable: false,
      fixDescription: 'Add PKCE with S256 code_challenge_method to all OAuth authorization flows',
    });
  },
});
