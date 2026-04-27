import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { API_KEY_PATTERNS } from '../../core/patterns.js';

export const cfg002 = defineCheck({
  id: 'CFG-002',
  name: 'API Key Exposure',
  category: 'config',
  severity: 'critical',
  description: 'Check for exposed API keys and secrets in config files',

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      // Skip .env files — they're expected to contain keys
      if (config.format === 'env') continue;

      const lines = config.raw.split('\n');
      for (let i = 0; i < lines.length; i++) {
        for (const { pattern, name } of API_KEY_PATTERNS) {
          if (pattern.test(lines[i])) {
            evidence.push({
              file: config.filePath,
              line: i + 1,
              snippet: lines[i].trim().slice(0, 80) + (lines[i].trim().length > 80 ? '...' : ''),
              detail: `Found ${name}`,
            });
          }
        }
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'No API keys found in config files',
      failed: (n) => `Found ${n} exposed API key(s) in config files`,
    });
  },
});
