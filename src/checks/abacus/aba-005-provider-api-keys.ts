import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { isEnvReference, literalSecret, mask, settingsConfigs } from './shared.js';

const KEY_FIELDS = ['apiKey', 'api_key', 'token', 'accessToken'];

export const aba005 = defineCheck({
  id: 'ABA-005',
  name: 'Abacus.AI Plaintext Provider API Key',
  category: 'coding-agent',
  severity: 'critical',
  description: 'Detect literal model-provider API keys in Abacus.AI `providers.<id>.options` (local provider loop) or request `headers` instead of `apiKeyEnvVar`',
  supportedAgents: ['abacus'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    for (const config of settingsConfigs(ctx.configs)) {
      const providers = config.data.providers;
      if (!providers || typeof providers !== 'object' || Array.isArray(providers)) continue;
      for (const [id, raw] of Object.entries(providers as Record<string, unknown>)) {
        const options = (raw as Record<string, unknown> | undefined)?.options as Record<string, unknown> | undefined;
        if (!options || typeof options !== 'object') continue;
        for (const field of KEY_FIELDS) {
          const value = options[field];
          if (typeof value !== 'string' || value.trim().length < 8 || isEnvReference(value)) continue;
          evidence.push({
            file: config.filePath,
            snippet: `providers.${id}.options.${field}: ${mask(value)}`,
            detail: `Plaintext API key for local provider "${id}" — readable by anything that can read the config`,
          });
        }
        // Providers doc: `options.headers` are sent with every request — an
        // `Authorization: Bearer <key>` there is the same key in another place
        const headers = options.headers;
        if (headers && typeof headers === 'object' && !Array.isArray(headers)) {
          for (const [name, value] of Object.entries(headers as Record<string, unknown>)) {
            if (typeof value !== 'string' || !literalSecret(name, value)) continue;
            evidence.push({
              file: config.filePath,
              snippet: `providers.${id}.options.headers.${name}: ${mask(value)}`,
              detail: `Plaintext credential in a request header for local provider "${id}" — readable by anything that can read the config`,
            });
          }
        }
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'No plaintext provider API keys in Abacus.AI config',
      failed: (n) => `Found ${n} plaintext provider API key(s) in Abacus.AI config`,
      fixDescription: 'Remove the key from providers.<id>.options, set providers.<id>.apiKeyEnvVar to an environment variable that holds it, and rotate the key',
    });
  },
});
