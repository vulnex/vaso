import type { CheckModule, ScanContext, CheckResult, Evidence } from '../../core/types.js';

const AUTHORIZE_URL_PATTERN = /\/authorize|\/authorization/;
const CODE_CHALLENGE_PATTERN = /code_challenge/;
const CODE_VERIFIER_PATTERN = /code_verifier/;
const PLAIN_CHALLENGE_PATTERN = /code_challenge_method['":\s]*['"]?plain/i;
const TOKEN_EXCHANGE_PATTERN = /\/token|grant_type|authorization_code/;

const SEARCH_RADIUS = 15;

export const mcp013: CheckModule = {
  id: 'MCP-013',
  name: 'Missing PKCE',
  category: 'mcp',
  severity: 'critical',
  description: 'Detect OAuth authorization flows without PKCE (Proof Key for Code Exchange) protection',
  supportedAgents: ['mcp'],

  async run(ctx: ScanContext): Promise<CheckResult> {
    const evidence: Evidence[] = [];
    const mcpServerSources = ctx.mcpServerSources ?? [];

    for (const source of mcpServerSources) {
      if (!source.sourceCode) continue;
      const lines = source.sourceCode.split('\n');
      const filePath = source.localPath ?? source.serverName;

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];

        // Detect OAuth authorize URL construction without PKCE
        if (AUTHORIZE_URL_PATTERN.test(line)) {
          const start = Math.max(0, i - SEARCH_RADIUS);
          const end = Math.min(lines.length, i + SEARCH_RADIUS + 1);
          const nearbyCode = lines.slice(start, end).join('\n');

          if (!CODE_CHALLENGE_PATTERN.test(nearbyCode)) {
            evidence.push({
              file: filePath,
              line: i + 1,
              snippet: line.trim(),
              detail: 'OAuth authorization URL constructed without PKCE code_challenge parameter',
            });
          }
        }

        // Detect plain code_challenge_method (should be S256)
        if (PLAIN_CHALLENGE_PATTERN.test(line)) {
          evidence.push({
            file: filePath,
            line: i + 1,
            snippet: line.trim(),
            detail: 'PKCE code_challenge_method set to "plain" — must use "S256" for security',
          });
        }

        // Detect token exchange without code_verifier
        if (TOKEN_EXCHANGE_PATTERN.test(line) && /grant_type.*authorization_code|authorization_code.*grant_type/.test(line)) {
          const start = Math.max(0, i - SEARCH_RADIUS);
          const end = Math.min(lines.length, i + SEARCH_RADIUS + 1);
          const nearbyCode = lines.slice(start, end).join('\n');

          if (!CODE_VERIFIER_PATTERN.test(nearbyCode)) {
            evidence.push({
              file: filePath,
              line: i + 1,
              snippet: line.trim(),
              detail: 'Token exchange with authorization_code grant but no code_verifier — PKCE not enforced',
            });
          }
        }
      }
    }

    return {
      id: 'MCP-013',
      name: 'Missing PKCE',
      category: 'mcp',
      severity: 'critical',
      passed: evidence.length === 0,
      message: evidence.length === 0
        ? 'OAuth flows properly implement PKCE'
        : `Found ${evidence.length} OAuth flow(s) without PKCE protection`,
      evidence: evidence.length > 0 ? evidence : undefined,
      fixable: false,
      fixDescription: 'Add PKCE with S256 code_challenge_method to all OAuth authorization flows',
    };
  },
};
