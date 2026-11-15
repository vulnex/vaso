import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { AUTH_CODE_GRANT, isAuthorizeRequest } from '../../mcp/oauth-context.js';
import { sourceSegments, nearbyText, blockText, isStringConstant } from '../../mcp/source-segments.js';
import { sourceSnippet } from '../../mcp/source-snippet.js';

const CODE_CHALLENGE_PATTERN = /code_challenge/;
const CODE_VERIFIER_PATTERN = /code_verifier/;
const PLAIN_CHALLENGE_PATTERN = /code_challenge_method['":\s]*['"]?plain/i;

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
      const segments = sourceSegments(source.sourceCode, { python: source.language === 'python' });
      const filePath = source.localPath ?? source.serverName;
      const python = source.language === 'python';
      // The flow's own block, not a fixed window: PKCE is often set further
      // down the same function (GitLab's proxy, ~60 lines)
      const around = (i: number) => `${nearbyText(segments, i, SEARCH_RADIUS)}\n${blockText(segments, i, python)}`;

      for (let i = 0; i < segments.length; i++) {
        const line = segments[i].text;

        const trimmed = line.trim();
        if (trimmed.startsWith('//') || trimmed.startsWith('*')) continue;

        // Detect OAuth authorize URL construction without PKCE
        // A route the server handles forwards the client's PKCE parameters.
        // A string constant naming the endpoint is not a request
        if (isAuthorizeRequest(line) && !isStringConstant(line)) {
          const nearbyCode = around(i);

          if (!CODE_CHALLENGE_PATTERN.test(nearbyCode)) {
            evidence.push({
              file: filePath,
              line: segments[i].line,
              snippet: sourceSnippet(source, line),
              detail: 'OAuth authorization URL constructed without PKCE code_challenge parameter',
            });
          }
        }

        // Detect plain code_challenge_method (should be S256)
        if (PLAIN_CHALLENGE_PATTERN.test(line)) {
          evidence.push({
            file: filePath,
            line: segments[i].line,
            snippet: sourceSnippet(source, line),
            detail: 'PKCE code_challenge_method set to "plain" — must use "S256" for security',
          });
        }

        // Detect token exchange without code_verifier
        if (AUTH_CODE_GRANT.test(line)) {
          const nearbyCode = around(i);

          if (!CODE_VERIFIER_PATTERN.test(nearbyCode)) {
            evidence.push({
              file: filePath,
              line: segments[i].line,
              snippet: sourceSnippet(source, line),
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
