import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

interface ChannelSpec {
  name: string;
  /** Env keys that, when present, indicate the channel is enabled. */
  tokenKeys: string[];
  policyKey: string;
}

const CHANNELS: ChannelSpec[] = [
  { name: 'telegram',   tokenKeys: ['TELEGRAM_BOT_TOKEN', 'LYRIE_TELEGRAM_TOKEN'],   policyKey: 'LYRIE_TELEGRAM_DM_POLICY' },
  { name: 'whatsapp',   tokenKeys: ['LYRIE_WHATSAPP_TOKEN', 'LYRIE_WHATSAPP_PHONE_ID'], policyKey: 'LYRIE_WHATSAPP_DM_POLICY' },
  { name: 'discord',    tokenKeys: ['DISCORD_BOT_TOKEN', 'LYRIE_DISCORD_TOKEN'],     policyKey: 'LYRIE_DISCORD_DM_POLICY' },
  { name: 'slack',      tokenKeys: ['SLACK_BOT_TOKEN', 'LYRIE_SLACK_TOKEN'],         policyKey: 'LYRIE_SLACK_DM_POLICY' },
  { name: 'matrix',     tokenKeys: ['LYRIE_MATRIX_TOKEN'],                           policyKey: 'LYRIE_MATRIX_DM_POLICY' },
  { name: 'mattermost', tokenKeys: ['LYRIE_MATTERMOST_TOKEN'],                       policyKey: 'LYRIE_MATTERMOST_DM_POLICY' },
  { name: 'irc',        tokenKeys: ['LYRIE_IRC_SERVER', 'LYRIE_IRC_NICK'],           policyKey: 'LYRIE_IRC_DM_POLICY' },
  { name: 'feishu',     tokenKeys: ['LYRIE_FEISHU_TOKEN', 'LYRIE_FEISHU_APP_ID'],    policyKey: 'LYRIE_FEISHU_DM_POLICY' },
  { name: 'rocketchat', tokenKeys: ['LYRIE_ROCKETCHAT_TOKEN'],                       policyKey: 'LYRIE_ROCKETCHAT_DM_POLICY' },
  { name: 'webchat',    tokenKeys: ['LYRIE_WEBCHAT_PORT'],                           policyKey: 'LYRIE_WEBCHAT_DM_POLICY' },
];

function isPresent(v: unknown): boolean {
  return typeof v === 'string' && v.trim() !== '' && !/^\$\{?[A-Z_]+\}?$/.test(v.trim());
}

export const ly003 = defineCheck({
  id: 'LY-003',
  name: 'DM Pairing Policy Open on Live Channel',
  category: 'lyrie',
  severity: 'critical',
  description: 'Detect channels with credentials configured but DM policy unset or "open" — Lyrie\'s legacy default lets any unknown sender DM the agent. Affects Telegram, WhatsApp, Discord, Slack, Matrix, Mattermost, IRC, Feishu, Rocket.Chat, WebChat.',
  supportedAgents: ['lyrie'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    for (const config of ctx.configs) {
      for (const ch of CHANNELS) {
        const enabled = ch.tokenKeys.some(k => isPresent(config.data[k]));
        if (!enabled) continue;

        const policy = (config.data[ch.policyKey] as string | undefined)?.trim().toLowerCase();
        if (!policy || policy === 'open') {
          evidence.push({
            file: config.filePath,
            detail: `Channel "${ch.name}" is enabled but ${ch.policyKey} is ${policy ? `"${policy}"` : 'unset'} — unknown senders can DM the agent without operator approval`,
          });
        }
      }
    }
    return h.fromEvidence(evidence, {
      passed: 'All configured channels have a non-open DM policy',
      failed: count => `${count} configured channel(s) have DM policy "open" or unset`,
      fixDescription: 'For each affected channel, set LYRIE_<CHAN>_DM_POLICY=pairing (recommended) or =closed in .env',
    });
  },
});
