import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

const TOKEN_PASSTHROUGH_PATTERNS = [
  { pattern: /req(?:uest)?\.headers\.authorization.*(?:fetch|http\.request|axios|got|request\()/i, detail: 'Inbound authorization header forwarded to outbound request' },
  { pattern: /(?:fetch|http\.request|axios|got|request)\s*\(.*req(?:uest)?\.headers\.authorization/i, detail: 'Inbound authorization header passed to outbound request' },
  { pattern: /(?:context|ctx)\.token.*(?:fetch|http\.request|axios|got)/i, detail: 'Context token forwarded to downstream API call' },
  { pattern: /(?:fetch|http\.request|axios|got).*(?:context|ctx)\.token/i, detail: 'Context token passed to downstream API' },
  { pattern: /headers\s*:\s*\{[^}]*authorization\s*:\s*req(?:uest)?\.headers/i, detail: 'Authorization header copied from inbound to outbound request' },
  { pattern: /headers\s*:\s*\{[^}]*[Bb]earer\s*.*req(?:uest)?\.headers/i, detail: 'Bearer token extracted from request and forwarded downstream' },
  { pattern: /authorization\s*:\s*[`'"]\s*Bearer\s*\$\{.*(?:req|request|ctx|context).*token/i, detail: 'Token from request context interpolated into outbound Authorization header' },
];

export const mcp015 = defineCheck({
  id: 'MCP-015',
  name: 'Token Passthrough',
  category: 'mcp',
  severity: 'critical',
  description: 'Detect MCP servers forwarding received auth tokens to downstream APIs (confused deputy risk)',
  supportedAgents: ['mcp'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    const mcpServerSources = ctx.mcpServerSources ?? [];

    for (const source of mcpServerSources) {
      if (!source.sourceCode) continue;
      const lines = source.sourceCode.split('\n');
      const filePath = source.localPath ?? source.serverName;

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];

        // Skip comment lines
        if (line.trim().startsWith('//') || line.trim().startsWith('*')) continue;

        for (const { pattern, detail } of TOKEN_PASSTHROUGH_PATTERNS) {
          if (pattern.test(line)) {
            evidence.push({
              file: filePath,
              line: i + 1,
              snippet: line.trim(),
              detail,
            });
            break;
          }
        }
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'No token passthrough patterns detected',
      failed: (n) => `Found ${n} token passthrough pattern(s) — tokens may be forwarded to downstream services`,
    });
  },
});
