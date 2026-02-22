import type { CheckModule, ScanContext, CheckResult, Evidence } from '../../core/types.js';
import { OAUTH_SECRET_PATTERNS, OAUTH_TOKEN_VALUE_PATTERNS } from '../../core/patterns.js';
import { shannonEntropy } from '../../analyzers/entropy.js';

const HIGH_ENTROPY_THRESHOLD = 4.5;
const MIN_SECRET_LENGTH = 16;

function maskValue(value: string): string {
  if (value.length <= 8) return '*'.repeat(value.length);
  return value.slice(0, 8) + '*'.repeat(Math.max(0, value.length - 8));
}

export const mcp012: CheckModule = {
  id: 'MCP-012',
  name: 'OAuth Client Secret Exposure',
  category: 'mcp',
  severity: 'critical',
  description: 'Check for plaintext OAuth client secrets, access tokens, and refresh tokens in MCP config env blocks',
  supportedAgents: ['mcp'],

  async run(ctx: ScanContext): Promise<CheckResult> {
    const evidence: Evidence[] = [];
    const mcpConfigs = ctx.mcpConfigs ?? [];

    for (const config of mcpConfigs) {
      for (const server of config.servers) {
        if (!server.env) continue;

        for (const [key, value] of Object.entries(server.env)) {
          // Skip env var references like ${VAR}
          if (/^\$\{.*\}$/.test(value) || /^\$[A-Z_]+$/.test(value)) continue;

          // Check key names against OAuth secret patterns
          for (const { pattern, name } of OAUTH_SECRET_PATTERNS) {
            if (pattern.test(key)) {
              evidence.push({
                file: config.filePath,
                snippet: `Server "${server.name}": ${key}=${maskValue(value)}`,
                detail: `Plaintext ${name} in env block`,
              });
              break;
            }
          }

          // Check values against OAuth token value patterns
          for (const { pattern, name } of OAUTH_TOKEN_VALUE_PATTERNS) {
            if (pattern.test(value)) {
              const alreadyCaught = evidence.some(e =>
                e.file === config.filePath && e.snippet?.includes(server.name) && e.snippet?.includes(key)
              );
              if (!alreadyCaught) {
                evidence.push({
                  file: config.filePath,
                  snippet: `Server "${server.name}": ${key}=${maskValue(value)}`,
                  detail: `Detected ${name} value in env block`,
                });
              }
              break;
            }
          }

          // Entropy check for secret-named vars
          const secretKeyPattern = /(?:client[_-]?secret|oauth[_-]?secret|refresh[_-]?token|access[_-]?token)/i;
          if (secretKeyPattern.test(key) && value.length >= MIN_SECRET_LENGTH) {
            const entropy = shannonEntropy(value);
            if (entropy > HIGH_ENTROPY_THRESHOLD) {
              const alreadyCaught = evidence.some(e =>
                e.file === config.filePath && e.snippet?.includes(server.name) && e.snippet?.includes(key)
              );
              if (!alreadyCaught) {
                evidence.push({
                  file: config.filePath,
                  snippet: `Server "${server.name}": ${key}=${maskValue(value)}`,
                  detail: `High-entropy value (${entropy.toFixed(1)} bits) in OAuth secret env var`,
                });
              }
            }
          }
        }
      }
    }

    return {
      id: 'MCP-012',
      name: 'OAuth Client Secret Exposure',
      category: 'mcp',
      severity: 'critical',
      passed: evidence.length === 0,
      message: evidence.length === 0
        ? 'No exposed OAuth credentials found in MCP configs'
        : `Found ${evidence.length} exposed OAuth credential(s) in MCP configs`,
      evidence: evidence.length > 0 ? evidence : undefined,
      fixable: evidence.length > 0,
      fixDescription: 'Move OAuth secrets to a secrets manager or use environment variable references (e.g., ${CLIENT_SECRET})',
    };
  },
};
