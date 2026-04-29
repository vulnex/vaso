import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { shannonEntropy } from '../../analyzers/entropy.js';

const SECRET_KEY_NAMES = /(?:api[_-]?key|token|secret|password|credential|auth)/i;
const KNOWN_KEY_PREFIXES = [
  /^sk-or-v1-[A-Za-z0-9]{32,}/,
  /^sk-ant-[A-Za-z0-9_-]{20,}/,
  /^sk-[A-Za-z0-9]{20,}/,
  /^ghp_[A-Za-z0-9]{20,}/,
  /^xox[baprs]-[A-Za-z0-9-]{10,}/,
  /^AIza[0-9A-Za-z_-]{30,}/, // Google API key
];
const HIGH_ENTROPY_THRESHOLD = 4.5;
const MIN_LENGTH = 20;
const ENV_REF_PATTERN = /^\$\{?[A-Z_][A-Z0-9_]*\}?$/;

function isSecretValue(value: string): boolean {
  if (value.length < MIN_LENGTH) return false;
  if (ENV_REF_PATTERN.test(value)) return false;
  if (KNOWN_KEY_PREFIXES.some(p => p.test(value))) return true;
  return shannonEntropy(value) > HIGH_ENTROPY_THRESHOLD;
}

function walkEnv(env: Record<string, unknown>, file: string, prefix: string, evidence: Evidence[]): void {
  for (const [key, value] of Object.entries(env)) {
    if (typeof value !== 'string') continue;
    if (!SECRET_KEY_NAMES.test(key) && !isSecretValue(value)) continue;
    if (!isSecretValue(value)) continue;
    evidence.push({
      file,
      snippet: `${prefix}${key}=${value.slice(0, 8)}…`,
      detail: 'Plaintext secret in Gemini settings — use $-references or external env',
    });
  }
}

export const gem001 = defineCheck({
  id: 'GEM-001',
  name: 'Plaintext API Key in Gemini Settings',
  category: 'coding-agent',
  severity: 'critical',
  description: 'Detect API keys or tokens stored in plaintext inside ~/.gemini/settings.json',
  supportedAgents: ['gemini-cli'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    for (const config of ctx.configs) {
      const env = config.data.env as Record<string, unknown> | undefined;
      if (env && typeof env === 'object') walkEnv(env, config.filePath, 'env.', evidence);

      const mcpServers = config.data.mcpServers as Record<string, unknown> | undefined;
      if (mcpServers && typeof mcpServers === 'object') {
        for (const [name, server] of Object.entries(mcpServers)) {
          if (!server || typeof server !== 'object') continue;
          const serverEnv = (server as Record<string, unknown>).env as Record<string, unknown> | undefined;
          if (serverEnv && typeof serverEnv === 'object') {
            walkEnv(serverEnv, config.filePath, `mcpServers.${name}.env.`, evidence);
          }
        }
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'No plaintext API keys detected in Gemini settings',
      failed: (n) => `Found ${n} plaintext credential(s) in Gemini settings`,
      fixDescription: 'Move keys to environment variables (GEMINI_API_KEY, GOOGLE_API_KEY) — Gemini reads them from process env',
    });
  },
});
