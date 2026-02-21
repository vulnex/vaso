import type { CheckModule, ScanContext, CheckResult } from '../../core/types.js';
import { getNestedValue } from '../../core/utils.js';

export const nb011: CheckModule = {
  id: 'NB-011',
  name: 'No Rate Limiting',
  category: 'nanobot',
  severity: 'warning',
  description: 'Check if no rate limiting is configured on any channel',
  supportedAgents: ['nanobot'],

  async run(ctx: ScanContext): Promise<CheckResult> {
    const evidence = [];
    for (const config of ctx.configs) {
      // Check global rate limit
      const globalRateLimit = getNestedValue(config.data, 'rateLimit')
        ?? getNestedValue(config.data, 'rateLimiting')
        ?? getNestedValue(config.data, 'security.rateLimit');

      const channels = config.data.channels as Record<string, Record<string, unknown>> | undefined;
      if (!channels || typeof channels !== 'object') {
        // No channels — check global only
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
    return {
      id: 'NB-011', name: 'No Rate Limiting', category: 'nanobot',
      severity: 'warning', passed: evidence.length === 0,
      message: evidence.length === 0
        ? 'Rate limiting is configured'
        : 'Channel(s) found without rate limiting — vulnerable to abuse',
      evidence: evidence.length > 0 ? evidence : undefined,
      fixable: true, fixDescription: 'Add rate limiting to channels or set a global rateLimit in config',
    };
  },
};
