import { defineCheck } from '../../core/check-builder.js';
import { getNestedValue } from '../../core/utils.js';

export const zc007 = defineCheck({
  id: 'ZC-007',
  name: 'Channel Wildcard Users',
  category: 'zeroclaw',
  severity: 'critical',
  description: 'Detect "*" in allowed_users for any channel, granting unrestricted access',
  supportedAgents: ['zeroclaw'],

  async run(ctx, h) {
    const evidence = [];

    for (const config of ctx.configs) {
      const channels = getNestedValue(config.data, 'channels') as Record<string, unknown> | undefined;

      if (channels && typeof channels === 'object') {
        for (const [channelName, channelConfig] of Object.entries(channels)) {
          if (!channelConfig || typeof channelConfig !== 'object') continue;

          const allowedUsers = (channelConfig as Record<string, unknown>).allowed_users;

          if (Array.isArray(allowedUsers) && allowedUsers.includes('*')) {
            evidence.push({
              file: config.filePath,
              detail: `Channel "${channelName}" has allowed_users=["*"] — any user can interact`,
            });
          }
        }
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'No channels have wildcard allowed_users',
      failed: (n) => `Found ${n} channel(s) with wildcard allowed_users`,
      fixable: true,
      fixDescription: 'Replace "*" in allowed_users with explicit user identifiers',
    });
  },

  async fix() {
    return { checkId: 'ZC-007', applied: false, message: 'Manual action required: replace "*" in allowed_users with specific user identifiers for each channel' };
  },
});
