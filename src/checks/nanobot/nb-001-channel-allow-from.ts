import type { CheckModule, ScanContext, CheckResult } from '../../core/types.js';

export const nb001: CheckModule = {
  id: 'NB-001',
  name: 'Empty Channel allowFrom',
  category: 'nanobot',
  severity: 'critical',
  description: 'Check if any channel has an empty allowFrom list (no access control)',
  supportedAgents: ['nanobot'],

  async run(ctx: ScanContext): Promise<CheckResult> {
    const evidence = [];
    for (const config of ctx.configs) {
      const channels = config.data.channels as Record<string, Record<string, unknown>> | undefined;
      if (!channels || typeof channels !== 'object') continue;
      for (const [name, ch] of Object.entries(channels)) {
        if (Array.isArray(ch.allowFrom) && ch.allowFrom.length === 0) {
          evidence.push({
            file: config.filePath,
            detail: `Channel "${name}" has empty allowFrom — anyone can send messages`,
          });
        }
      }
    }
    return {
      id: 'NB-001', name: 'Empty Channel allowFrom', category: 'nanobot',
      severity: 'critical', passed: evidence.length === 0,
      message: evidence.length === 0
        ? 'All channels have allowFrom configured'
        : 'Channels with empty allowFrom detected — no access control',
      evidence: evidence.length > 0 ? evidence : undefined,
      fixable: true, fixDescription: 'Add allowed user IDs to channel allowFrom arrays',
    };
  },
};
