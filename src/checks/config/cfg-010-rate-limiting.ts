import { defineCheck } from '../../core/check-builder.js';
import { CODING_AGENTS } from '../../core/types.js';
import { fixFirstConfig } from '../../remediation/config-writer.js';
import { getNestedValue } from '../../core/utils.js';

export const cfg010 = defineCheck({
  id: 'CFG-010',
  name: 'No Rate Limiting',
  category: 'config',
  severity: 'warning',
  description: 'Check if rate limiting is configured for the gateway',
  excludedAgents: CODING_AGENTS,

  async run(ctx, h) {
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

    return h.result({
      passed: found,
      message: found
        ? 'Rate limiting is configured'
        : 'No rate limiting configured — gateway is vulnerable to abuse',
      fixable: true,
      fixDescription: 'Add rate limiting configuration',
    });
  },

  async fix(ctx) {
    const rateLimit = { max: 60, window: '1m' };
    return fixFirstConfig(ctx.configs, {
      checkId: 'CFG-010',
      env: 'RATE_LIMIT',
      path: 'rateLimit',
      value: rateLimit,
      envValue: '60/1m',
      message: 'Added rate limiting (60 requests per minute)',
      noConfigMessage: 'No config file found',
    });
  },
});
