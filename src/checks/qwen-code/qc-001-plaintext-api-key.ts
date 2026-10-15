import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { shannonEntropy } from '../../analyzers/entropy.js';
import { isPlaceholderSecret } from '../../core/patterns.js';

const KNOWN_KEY_PREFIXES = [
  /^sk-or-v1-[A-Za-z0-9]{32,}/,
  /^sk-ant-[A-Za-z0-9_-]{20,}/,
  /^sk-[A-Za-z0-9]{20,}/,
  /^ghp_[A-Za-z0-9]{20,}/,
  /^xox[baprs]-[A-Za-z0-9-]{10,}/,
  /^AIza[0-9A-Za-z_-]{30,}/,
];
const HIGH_ENTROPY_THRESHOLD = 4.5;
const MIN_LENGTH = 20;
const ENV_REF_PATTERN = /^\$\{?[A-Z_][A-Z0-9_]*\}?$/;
// Authorization-style header values carry the secret after the scheme
const AUTH_SCHEME = /^(?:bearer|basic|token)\s+/i;

function isSecretValue(value: string): boolean {
  if (value.length < MIN_LENGTH) return false;
  if (isPlaceholderSecret(value)) return false;
  if (ENV_REF_PATTERN.test(value)) return false;
  if (KNOWN_KEY_PREFIXES.some(p => p.test(value))) return true;
  return shannonEntropy(value) > HIGH_ENTROPY_THRESHOLD;
}

function walkEnv(env: Record<string, unknown>, file: string, prefix: string, evidence: Evidence[]): void {
  for (const [key, raw] of Object.entries(env)) {
    if (typeof raw !== 'string') continue;
    const value = raw.replace(AUTH_SCHEME, '');
    if (!isSecretValue(value)) continue;
    evidence.push({
      file,
      snippet: `${prefix}${key}=${value.slice(0, 8)}…`,
      detail: 'Plaintext secret in Qwen settings — keys here are documented as lowest-priority fallback; prefer process env',
    });
  }
}

export const qc001 = defineCheck({
  id: 'QC-001',
  name: 'Plaintext API Key in Qwen Settings',
  category: 'coding-agent',
  severity: 'critical',
  description: 'Detect API keys stored in plaintext in ~/.qwen/settings.json under env, modelProviders, security.auth.apiKey or MCP server env/headers',
  supportedAgents: ['qwen-code'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    for (const config of ctx.configs) {
      const env = config.data.env as Record<string, unknown> | undefined;
      if (env && typeof env === 'object') walkEnv(env, config.filePath, 'env.', evidence);

      // Deprecated but still honoured (settings.md: "Migrate to modelProviders
      // with envKey instead")
      const auth = (config.data.security as Record<string, unknown> | undefined)?.auth as Record<string, unknown> | undefined;
      if (auth && typeof auth === 'object' && typeof auth.apiKey === 'string' && isSecretValue(auth.apiKey)) {
        evidence.push({
          file: config.filePath,
          snippet: `security.auth.apiKey=${auth.apiKey.slice(0, 8)}…`,
          detail: 'Inline API key in the deprecated security.auth.apiKey setting — use a modelProviders entry with envKey instead',
        });
      }

      const providers = config.data.modelProviders as Record<string, unknown> | undefined;
      if (providers && typeof providers === 'object') {
        for (const [provName, list] of Object.entries(providers)) {
          if (!Array.isArray(list)) continue;
          for (let i = 0; i < list.length; i++) {
            const item = list[i];
            if (!item || typeof item !== 'object') continue;
            const obj = item as Record<string, unknown>;
            const apiKey = obj.apiKey;
            if (typeof apiKey === 'string' && isSecretValue(apiKey)) {
              evidence.push({
                file: config.filePath,
                snippet: `modelProviders.${provName}[${i}].apiKey=${apiKey.slice(0, 8)}…`,
                detail: 'Inline apiKey in modelProviders entry — use envKey reference instead',
              });
            }
          }
        }
      }

      const mcpServers = config.data.mcpServers as Record<string, unknown> | undefined;
      if (mcpServers && typeof mcpServers === 'object') {
        for (const [name, server] of Object.entries(mcpServers)) {
          if (!server || typeof server !== 'object') continue;
          // env and headers (settings.md: "A map of HTTP headers to send with
          // requests to url or httpUrl") both hold literal values
          for (const field of ['env', 'headers'] as const) {
            const values = (server as Record<string, unknown>)[field] as Record<string, unknown> | undefined;
            if (values && typeof values === 'object') {
              walkEnv(values, config.filePath, `mcpServers.${name}.${field}.`, evidence);
            }
          }
        }
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'No plaintext API keys detected in Qwen settings',
      failed: (n) => `Found ${n} plaintext credential(s) in Qwen settings`,
      fixDescription: 'Move keys to environment variables (referenced via envKey in modelProviders); rotate any key found here',
    });
  },
});
