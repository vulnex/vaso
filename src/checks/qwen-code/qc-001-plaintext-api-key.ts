import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { isKnownSecretValue, isSecretNamedValue } from '../../analyzers/secret-values.js';
import { secretShape } from '../../core/patterns.js';

// …or a name ending in KEY / PAT (MISTRAL_KEY, GITLAB_PAT)
const SECRET_KEY_NAMES = /(?:api[_-]?key|token|secret|password|passwd|credential|auth|private[_-]?key|(?:^|[_-])(?:key|pat)$)/i;
// Authorization-style header values carry the secret after the scheme
const AUTH_SCHEME = /^(?:bearer|basic|token)\s+/i;

/**
 * A secret-like name with a known key format or a random-looking value
 * (hex and UUID keys included), or a recognised key format under any name
 * — entropy alone also matches user agents, long paths and IDs. References,
 * placeholders, public keys and client IDs are never secrets.
 */
function isSecretValue(key: string, value: string): boolean {
  return SECRET_KEY_NAMES.test(key) ? isSecretNamedValue(key, value) : isKnownSecretValue(value);
}

function walkEnv(env: Record<string, unknown>, file: string, prefix: string, evidence: Evidence[]): void {
  for (const [key, raw] of Object.entries(env)) {
    if (typeof raw !== 'string') continue;
    const value = raw.replace(AUTH_SCHEME, '');
    if (!isSecretValue(key, value)) continue;
    evidence.push({
      file,
      snippet: `${prefix}${key}=${secretShape(value)}`,
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
      if (auth && typeof auth === 'object' && typeof auth.apiKey === 'string' && isSecretValue('apiKey', auth.apiKey)) {
        evidence.push({
          file: config.filePath,
          snippet: `security.auth.apiKey=${secretShape(auth.apiKey)}`,
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
            if (typeof apiKey === 'string' && isSecretValue('apiKey', apiKey)) {
              evidence.push({
                file: config.filePath,
                snippet: `modelProviders.${provName}[${i}].apiKey=${secretShape(apiKey)}`,
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
