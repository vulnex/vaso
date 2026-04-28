import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { updateEnvFile } from '../../remediation/config-writer.js';

const CHANNEL_TOKEN_KEYS = [
  'TELEGRAM_BOT_TOKEN', 'LYRIE_TELEGRAM_TOKEN',
  'DISCORD_BOT_TOKEN', 'LYRIE_DISCORD_TOKEN',
  'SLACK_BOT_TOKEN', 'LYRIE_SLACK_TOKEN',
  'LYRIE_WHATSAPP_TOKEN',
  'LYRIE_MATRIX_TOKEN',
  'LYRIE_MATTERMOST_TOKEN',
  'LYRIE_FEISHU_TOKEN',
  'LYRIE_ROCKETCHAT_TOKEN',
] as const;

function isPresent(v: unknown): boolean {
  return typeof v === 'string' && v.trim() !== '' && !/^\$\{?[A-Z_]+\}?$/.test(v.trim());
}

export const ly018 = defineCheck({
  id: 'LY-018',
  name: 'Development NODE_ENV with Production Channels',
  category: 'lyrie',
  severity: 'critical',
  description: 'Detect NODE_ENV=development while one or more channel tokens are configured — verbose logging and dev-only paths are active alongside live channel bots, risking secret leakage in logs.',
  supportedAgents: ['lyrie'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    for (const config of ctx.configs) {
      const nodeEnv = config.data.NODE_ENV as string | undefined;
      if (nodeEnv && nodeEnv !== 'development') continue;
      // Treat unset NODE_ENV the same as development (Lyrie's default per config.ts)
      const liveChannels = CHANNEL_TOKEN_KEYS.filter(k => isPresent(config.data[k]));
      if (liveChannels.length === 0) continue;

      evidence.push({
        file: config.filePath,
        detail: `NODE_ENV=${nodeEnv ?? 'development (default)'} with ${liveChannels.length} channel token(s) configured — debug logs may leak secrets and message content`,
      });
    }
    return h.fromEvidence(evidence, {
      passed: 'NODE_ENV is production or no channels are configured',
      failed: () => 'NODE_ENV=development with live channel tokens configured',
      fixable: true,
      fixDescription: 'Set NODE_ENV=production in .env when running Lyrie with real channel tokens',
    });
  },

  async fix(ctx) {
    for (const config of ctx.configs) {
      if (config.format === 'env') {
        await updateEnvFile(config.filePath, 'NODE_ENV', 'production');
        return { checkId: 'LY-018', applied: true, message: 'Set NODE_ENV=production' };
      }
    }
    return { checkId: 'LY-018', applied: false, message: 'No .env file found' };
  },
});
