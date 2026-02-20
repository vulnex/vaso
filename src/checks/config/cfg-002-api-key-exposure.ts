import type { CheckModule, ScanContext, CheckResult, Evidence } from '../../core/types.js';
import { API_KEY_PATTERNS } from '../../core/patterns.js';

export const cfg002: CheckModule = {
  id: 'CFG-002',
  name: 'API Key Exposure',
  category: 'config',
  severity: 'critical',
  description: 'Check for exposed API keys and secrets in config files',

  async run(ctx: ScanContext): Promise<CheckResult> {
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

    return {
      id: 'CFG-002',
      name: 'API Key Exposure',
      category: 'config',
      severity: 'critical',
      passed: evidence.length === 0,
      message: evidence.length === 0
        ? 'No API keys found in config files'
        : `Found ${evidence.length} exposed API key(s) in config files`,
      evidence: evidence.length > 0 ? evidence : undefined,
    };
  },
};
