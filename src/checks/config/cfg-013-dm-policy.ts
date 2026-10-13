import { defineCheck } from '../../core/check-builder.js';
import { CODING_AGENTS } from '../../core/types.js';
import { getNestedValue } from '../../core/utils.js';

export const cfg013 = defineCheck({
  id: 'CFG-013',
  name: 'DM Policy Open',
  category: 'config',
  severity: 'warning',
  description: 'Check if direct message policy allows unrestricted messaging',
  excludedAgents: CODING_AGENTS,

  async run(ctx, h) {
    for (const config of ctx.configs) {
      const dmPolicy = getNestedValue(config.data, 'dm.policy') ??
                       getNestedValue(config.data, 'messaging.dm') ??
                       getNestedValue(config.data, 'directMessage.policy');

      // OpenClaw 2026.x: per channel, channels.<ch>.dmPolicy = pairing | allowlist | open | disabled
      const channels = config.data.channels;
      const openChannels = channels && typeof channels === 'object'
        ? Object.entries(channels as Record<string, unknown>)
            .filter(([, ch]) => (ch as Record<string, unknown> | null)?.dmPolicy === 'open')
            .map(([name]) => name)
        : [];
      if (openChannels.length > 0) {
        return h.result({
          passed: false,
          message: `DM policy is open on ${openChannels.join(', ')} — anyone can message the agent directly`,
          evidence: openChannels.map(name => ({ file: config.filePath, detail: `channels.${name}.dmPolicy: open` })),
          fixable: false,
          fixDescription: 'Set channels.<channel>.dmPolicy to "pairing" or "allowlist"',
        });
      }

      if (dmPolicy === 'open' || dmPolicy === 'unrestricted' || dmPolicy === 'allow_all') {
        return h.result({
          passed: false,
          message: 'DM policy is set to open — anyone can message the agent directly',
          evidence: [{ file: config.filePath, detail: `DM policy: ${String(dmPolicy)}` }],
          // The restricted value differs per framework (OpenClaw: channels.<ch>.dmPolicy
          // "pairing" | "allowlist"); writing a guess can make a strict loader reject the file
          fixable: false,
          fixDescription: 'Set DM policy to restricted or allowlist-only',
        });
      }
    }

    return h.passed('DM policy is not set to open');
  },
});
