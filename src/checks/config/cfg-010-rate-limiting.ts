import type { CheckModule, ScanContext, CheckResult } from '../../core/types.js';
import { getNestedValue } from '../../core/utils.js';

export const cfg010: CheckModule = {
  id: 'CFG-010',
  name: 'No Rate Limiting',
  category: 'config',
  severity: 'warning',
  description: 'Check if rate limiting is configured for the gateway',

  async run(ctx: ScanContext): Promise<CheckResult> {
    let found = false;

    for (const config of ctx.configs) {
      const rateLimit = getNestedValue(config.data, 'rateLimit') ??
                        getNestedValue(config.data, 'gateway.rateLimit') ??
                        getNestedValue(config.data, 'security.rateLimit') ??
                        getNestedValue(config.data, 'rateLimiting') ??
                        config.data.RATE_LIMIT;

      if (rateLimit) {
        found = true;
        break;
      }
    }

    return {
      id: 'CFG-010',
      name: 'No Rate Limiting',
      category: 'config',
      severity: 'warning',
      passed: found,
      message: found
        ? 'Rate limiting is configured'
        : 'No rate limiting configured — gateway is vulnerable to abuse',
      fixable: true,
      fixDescription: 'Add rate limiting configuration',
    };
  },
};
