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

      // OpenClaw 2026.x: per channel, channels.<ch>.dmPolicy = pairing | allowlist | open | disabled,
      // and each channels.<ch>.accounts.<id> may override it (2026.9.4 schema)
      const channels = config.data.channels;
      const openChannels: string[] = [];
      if (channels && typeof channels === 'object') {
        for (const [name, ch] of Object.entries(channels as Record<string, unknown>)) {
          const chRec = ch && typeof ch === 'object' ? ch as Record<string, unknown> : undefined;
          if (!chRec || chRec.enabled === false) continue;
          if (chRec.dmPolicy === 'open') openChannels.push(name);
          const accounts = chRec.accounts;
          if (accounts && typeof accounts === 'object' && !Array.isArray(accounts)) {
            for (const [id, acc] of Object.entries(accounts as Record<string, unknown>)) {
              const accRec = acc && typeof acc === 'object' ? acc as Record<string, unknown> : undefined;
              if (accRec?.enabled !== false && accRec?.dmPolicy === 'open') openChannels.push(`${name}.accounts.${id}`);
            }
          }
        }
      }
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
