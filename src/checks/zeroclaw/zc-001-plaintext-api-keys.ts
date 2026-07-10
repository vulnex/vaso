import { defineCheck } from '../../core/check-builder.js';
import { getNestedValue } from '../../core/utils.js';
import { API_KEY_PATTERNS } from '../../core/patterns.js';
import { fixFirstConfig } from '../../remediation/config-writer.js';

export const zc001 = defineCheck({
  id: 'ZC-001',
  name: 'Plaintext API Keys',
  category: 'zeroclaw',
  severity: 'critical',
  description: 'Detect secrets.encrypt=false with API keys present in config',
  supportedAgents: ['zeroclaw'],

  async run(ctx, h) {
    const evidence = [];

    for (const config of ctx.configs) {
      const encrypt = getNestedValue(config.data, 'secrets.encrypt');

      if (encrypt === false || encrypt === 'false') {
        for (const { pattern, name } of API_KEY_PATTERNS) {
          const matches = config.raw.match(pattern);
          if (matches) {
            evidence.push({
              file: config.filePath,
              detail: `secrets.encrypt=false and ${name} found in config`,
            });
          }
        }

        if (!evidence.some(e => e.file === config.filePath)) {
          evidence.push({
            file: config.filePath,
            detail: 'secrets.encrypt=false — API keys stored in plaintext',
          });
        }
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'Secret encryption is enabled or no API keys found',
      failed: (n) => `Found ${n} config(s) with plaintext API keys`,
      fixable: true,
      fixDescription: 'Set secrets.encrypt=true and re-encrypt API keys using zeroclaw secrets encrypt',
    });
  },

  async fix(ctx) {
    return fixFirstConfig(ctx.configs, {
      checkId: 'ZC-001',
      path: 'secrets.encrypt',
      value: true,
      message: 'Set secrets.encrypt=true — run "zeroclaw secrets encrypt" to encrypt existing keys',
      noConfigMessage: 'No TOML config file found',
    });
  },
});
