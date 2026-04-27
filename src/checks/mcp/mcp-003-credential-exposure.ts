import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { API_KEY_PATTERNS } from '../../core/patterns.js';
import { shannonEntropy } from '../../analyzers/entropy.js';

const HIGH_ENTROPY_THRESHOLD = 4.5;
const MIN_SECRET_LENGTH = 16;

export const mcp003 = defineCheck({
  id: 'MCP-003',
  name: 'Credential Exposure',
  category: 'mcp',
  severity: 'critical',
  description: 'Check for plaintext secrets in MCP server env blocks and config values',
  supportedAgents: ['mcp'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    const mcpConfigs = ctx.mcpConfigs ?? [];

    for (const config of mcpConfigs) {
      for (const server of config.servers) {
        if (!server.env) continue;

        for (const [key, value] of Object.entries(server.env)) {
          // Check against known API key patterns
          for (const { pattern, name } of API_KEY_PATTERNS) {
            if (pattern.test(value)) {
              evidence.push({
                file: config.filePath,
                snippet: `Server "${server.name}": ${key}=${value.slice(0, 8)}${'*'.repeat(Math.max(0, value.length - 8))}`,
                detail: `Plaintext ${name} in env block`,
              });
            }
          }

          // Check for high-entropy values that look like secrets
          const secretKeyPattern = /(?:key|token|secret|password|credential|auth|api_key|apikey|pass)/i;
          if (secretKeyPattern.test(key) && value.length >= MIN_SECRET_LENGTH) {
            const entropy = shannonEntropy(value);
            if (entropy > HIGH_ENTROPY_THRESHOLD) {
              // Avoid duplicate if already caught by pattern above
              const alreadyCaught = evidence.some(e =>
                e.file === config.filePath && e.snippet?.includes(server.name) && e.snippet?.includes(key)
              );
              if (!alreadyCaught) {
                evidence.push({
                  file: config.filePath,
                  snippet: `Server "${server.name}": ${key}=${value.slice(0, 8)}...`,
                  detail: `High-entropy value (${entropy.toFixed(1)} bits) in secret-named env var`,
                });
              }
            }
          }
        }
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'No plaintext credentials found in MCP configs',
      failed: (n) => `Found ${n} exposed credential(s) in MCP configs`,
      fixable: evidence.length > 0,
      fixDescription: 'Move secrets to environment variables or a secrets manager',
    });
  },
});
