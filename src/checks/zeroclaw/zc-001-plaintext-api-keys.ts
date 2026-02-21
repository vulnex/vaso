import type { CheckModule, ScanContext, CheckResult } from '../../core/types.js';
import { getNestedValue } from '../../core/utils.js';
import { API_KEY_PATTERNS } from '../../core/patterns.js';

export const zc001: CheckModule = {
  id: 'ZC-001',
  name: 'Plaintext API Keys',
  category: 'zeroclaw',
  severity: 'critical',
  description: 'Detect secrets.encrypt=false with API keys present in config',
  supportedAgents: ['zeroclaw'],

  async run(ctx: ScanContext): Promise<CheckResult> {
    const evidence = [];

    for (const config of ctx.configs) {
      const encrypt = getNestedValue(config.data, 'secrets.encrypt');

      if (encrypt === false || encrypt === 'false') {
        // Encryption is disabled — scan raw content for API key patterns
        for (const { pattern, name } of API_KEY_PATTERNS) {
          const matches = config.raw.match(pattern);
          if (matches) {
            evidence.push({
              file: config.filePath,
              detail: `secrets.encrypt=false and ${name} found in config`,
            });
          }
        }

        // If no specific key pattern matched but encryption is still off, flag it
        if (!evidence.some(e => e.file === config.filePath)) {
          evidence.push({
            file: config.filePath,
            detail: 'secrets.encrypt=false — API keys stored in plaintext',
          });
        }
      }
    }

    return {
      id: 'ZC-001',
      name: 'Plaintext API Keys',
      category: 'zeroclaw',
      severity: 'critical',
      passed: evidence.length === 0,
      message: evidence.length === 0
        ? 'Secret encryption is enabled or no API keys found'
        : `Found ${evidence.length} config(s) with plaintext API keys`,
      evidence: evidence.length > 0 ? evidence : undefined,
      fixable: true,
      fixDescription: 'Set secrets.encrypt=true and re-encrypt API keys using zeroclaw secrets encrypt',
    };
  },
};
