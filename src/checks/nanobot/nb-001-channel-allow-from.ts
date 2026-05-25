import { defineCheck } from '../../core/check-builder.js';

export const nb001 = defineCheck({
  id: 'NB-001',
  name: 'Empty Channel allowFrom',
  category: 'nanobot',
  severity: 'critical',
  description: 'Check if any channel has an empty allowFrom list (no access control)',
  supportedAgents: ['nanobot'],

  async run(ctx, h) {
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
    return h.fromEvidence(evidence, {
      passed: 'All channels have allowFrom configured',
      failed: () => 'Channels with empty allowFrom detected — no access control',
      fixDescription: 'Add allowed user IDs to channel allowFrom arrays',
    });
  },
});
