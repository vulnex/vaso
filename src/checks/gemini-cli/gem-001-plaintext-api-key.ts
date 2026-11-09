import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { isKnownSecretValue, isSecretNamedValue } from '../../analyzers/secret-values.js';

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
          // `headers` (url/httpUrl servers) hold literal values just like `env`
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
      passed: 'No plaintext API keys detected in Gemini settings',
      failed: (n) => `Found ${n} plaintext credential(s) in Gemini settings`,
      fixDescription: 'Move keys to environment variables (GEMINI_API_KEY, GOOGLE_API_KEY) — Gemini reads them from process env',
    });
  },
});
