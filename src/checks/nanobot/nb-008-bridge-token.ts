import { defineCheck } from '../../core/check-builder.js';

export const nb008 = defineCheck({
  id: 'NB-008',
  name: 'Empty Bridge Token',
  category: 'nanobot',
  severity: 'warning',
  description: 'Check if WhatsApp bridge is enabled but bridge_token is empty or unset',
  supportedAgents: ['nanobot'],

  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const channels = config.data.channels as Record<string, Record<string, unknown>> | undefined;
      if (!channels || typeof channels !== 'object') continue;

      for (const [name, ch] of Object.entries(channels)) {
        const type = ch.type as string | undefined;
        const isBridge = type === 'whatsapp' || type === 'whatsapp-bridge'
          || type === 'bridge' || ch.bridge === true;

        if (!isBridge) continue;

        const token = ch.bridge_token ?? ch.bridgeToken ?? ch.token;

        if (!token || (typeof token === 'string' && token.trim() === '')) {
          evidence.push({
            file: config.filePath,
            detail: `Channel "${name}" has WhatsApp bridge enabled but bridge_token is empty or unset — unauthenticated bridge access`,
          });
        }
      }
    }
    return h.fromEvidence(evidence, {
      passed: 'All bridge channels have tokens configured',
      failed: () => 'Bridge channel(s) found with empty or missing bridge_token',
      fixDescription: 'Set a strong bridge_token for each WhatsApp bridge channel',
    });
  },
});
