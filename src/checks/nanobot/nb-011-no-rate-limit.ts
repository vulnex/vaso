import { defineCheck } from '../../core/check-builder.js';
import { getNestedValue } from '../../core/utils.js';
import { fixFirstConfig } from '../../remediation/config-writer.js';

export const nb011 = defineCheck({
  id: 'NB-011',
  name: 'No Rate Limiting',
  category: 'nanobot',
  severity: 'warning',
  description: 'Check if no rate limiting is configured on any channel',
  supportedAgents: ['nanobot'],

  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const globalRateLimit = getNestedValue(config.data, 'rateLimit')
        ?? getNestedValue(config.data, 'rateLimiting')
        ?? getNestedValue(config.data, 'security.rateLimit');

      const channels = config.data.channels as Record<string, Record<string, unknown>> | undefined;
      if (!channels || typeof channels !== 'object') {
        if (!globalRateLimit) {
          evidence.push({
            file: config.filePath,
            detail: 'No global rate limiting configured',
          });
        }
        continue;
      }

      for (const [name, ch] of Object.entries(channels)) {
        const channelRateLimit = ch.rateLimit ?? ch.rateLimiting ?? ch.maxMessagesPerMinute;

        if (!channelRateLimit && !globalRateLimit) {
          evidence.push({
            file: config.filePath,
            detail: `Channel "${name}" has no rate limiting (no channel-level or global rate limit) — vulnerable to abuse/DoS`,
          });
        }
      }
    }
    return h.fromEvidence(evidence, {
      passed: 'Rate limiting is configured',
      failed: () => 'Channel(s) found without rate limiting — vulnerable to abuse',
      fixable: true,
      fixDescription: 'Add rate limiting to channels or set a global rateLimit in config',
    });
  },

  async fix(ctx) {
    const rateLimit = { maxPerMinute: 30, maxPerHour: 500 };
    return fixFirstConfig(ctx.configs, {
      checkId: 'NB-011',
      path: 'rateLimit',
      value: rateLimit,
      message: 'Added global rate limit (30/min, 500/hr)',
      noConfigMessage: 'No JSON config file found',
    });
  },
});
