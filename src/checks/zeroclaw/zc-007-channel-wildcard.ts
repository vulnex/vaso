import type { CheckModule, ScanContext, CheckResult } from '../../core/types.js';
import { getNestedValue } from '../../core/utils.js';

export const zc007: CheckModule = {
  id: 'ZC-007',
  name: 'Channel Wildcard Users',
  category: 'zeroclaw',
  severity: 'critical',
  description: 'Detect "*" in allowed_users for any channel, granting unrestricted access',
  supportedAgents: ['zeroclaw'],

  async run(ctx: ScanContext): Promise<CheckResult> {
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

    return {
      id: 'ZC-007',
      name: 'Channel Wildcard Users',
      category: 'zeroclaw',
      severity: 'critical',
      passed: evidence.length === 0,
      message: evidence.length === 0
        ? 'No channels have wildcard allowed_users'
        : `Found ${evidence.length} channel(s) with wildcard allowed_users`,
      evidence: evidence.length > 0 ? evidence : undefined,
      fixable: true,
      fixDescription: 'Replace "*" in allowed_users with explicit user identifiers',
    };
  },
};
