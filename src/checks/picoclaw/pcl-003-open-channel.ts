import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { enabledChannels, isChatChannel, picoMainConfigs, stringList } from './shared.js';

export const pcl003 = defineCheck({
  id: 'PCL-003',
  name: 'PicoClaw Channel Open to Any Sender',
  category: 'picoclaw',
  severity: 'critical',
  description: 'PicoClaw accepts every sender on a channel whose allow_from is empty or contains "*" (an empty list is not deny-all). Anyone who finds the bot can drive the agent and its tools.',
  supportedAgents: ['picoclaw'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    for (const config of picoMainConfigs(ctx.configs)) {
      for (const ch of enabledChannels(config.data).filter(isChatChannel)) {
        const allow = stringList(ch.cfg.allow_from);
        if (allow.length > 0 && !allow.includes('*')) continue;
        evidence.push({
          file: config.filePath,
          snippet: `channel_list.${ch.name}.allow_from: ${JSON.stringify(allow)}`,
          detail: allow.length === 0
            ? `Enabled ${ch.type} channel has no allow_from list — PicoClaw accepts every sender`
            : `Enabled ${ch.type} channel allows "*" — every sender`,
        });
      }
    }
    return h.fromEvidence(evidence, {
      passed: 'Enabled PicoClaw channels restrict who can message the agent',
      failed: (n) => `${n} enabled PicoClaw channel(s) accept messages from anyone`,
      fixDescription: 'List the user IDs allowed to talk to the agent in channel_list.<name>.allow_from',
    });
  },
});
