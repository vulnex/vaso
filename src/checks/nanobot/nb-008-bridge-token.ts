import type { CheckModule, ScanContext, CheckResult, FixResult } from '../../core/types.js';

export const nb008: CheckModule = {
  id: 'NB-008',
  name: 'Empty Bridge Token',
  category: 'nanobot',
  severity: 'warning',
  description: 'Check if WhatsApp bridge is enabled but bridge_token is empty or unset',
  supportedAgents: ['nanobot'],

  async run(ctx: ScanContext): Promise<CheckResult> {
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
    return {
      id: 'NB-008', name: 'Empty Bridge Token', category: 'nanobot',
      severity: 'warning', passed: evidence.length === 0,
      message: evidence.length === 0
        ? 'All bridge channels have tokens configured'
        : 'Bridge channel(s) found with empty or missing bridge_token',
      evidence: evidence.length > 0 ? evidence : undefined,
      fixable: true, fixDescription: 'Set a strong bridge_token for each WhatsApp bridge channel',
    };
  },

  async fix(_ctx: ScanContext): Promise<FixResult> {
    return { checkId: 'NB-008', applied: false, message: 'Manual action required: generate and set a strong bridge_token for each WhatsApp bridge channel' };
  },
};
