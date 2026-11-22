import type { Evidence, ParsedConfig } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { envFile, envString, isConfigured, lyrieMergedEnvs } from './env.js';

interface ChannelSpec {
  name: string;
  /** Env keys that must ALL be set for the gateway to start the channel
   *  (packages/gateway/src/index.ts loadConfig `enabled`). */
  enableKeys: string[];
  policyKey: string;
  /** Allowlist keys the channel adapter itself enforces even under the
   *  open policy (only Telegram's AuthChecker does this in 3.4.0). */
  selfEnforcedAllowlist?: string[];
}

// WebChat is intentionally absent: in 3.4.0 its listener is a skeleton
// (nothing binds) — LY-010/LY-011 cover its exposure settings.
const CHANNELS: ChannelSpec[] = [
  { name: 'telegram',   enableKeys: ['LYRIE_TELEGRAM_TOKEN'], policyKey: 'LYRIE_TELEGRAM_DM_POLICY', selfEnforcedAllowlist: ['LYRIE_TELEGRAM_USERS', 'LYRIE_TELEGRAM_CHATS'] },
  { name: 'whatsapp',   enableKeys: ['LYRIE_WHATSAPP_PHONE_ID'], policyKey: 'LYRIE_WHATSAPP_DM_POLICY' },
  { name: 'discord',    enableKeys: ['LYRIE_DISCORD_TOKEN'], policyKey: 'LYRIE_DISCORD_DM_POLICY' },
  { name: 'slack',      enableKeys: ['LYRIE_SLACK_BOT_TOKEN'], policyKey: 'LYRIE_SLACK_DM_POLICY' },
  { name: 'matrix',     enableKeys: ['LYRIE_MATRIX_HOMESERVER', 'LYRIE_MATRIX_TOKEN'], policyKey: 'LYRIE_MATRIX_DM_POLICY' },
  { name: 'mattermost', enableKeys: ['LYRIE_MATTERMOST_URL', 'LYRIE_MATTERMOST_TOKEN'], policyKey: 'LYRIE_MATTERMOST_DM_POLICY' },
  { name: 'irc',        enableKeys: ['LYRIE_IRC_SERVER', 'LYRIE_IRC_NICK'], policyKey: 'LYRIE_IRC_DM_POLICY' },
  { name: 'feishu',     enableKeys: ['LYRIE_FEISHU_APP_ID', 'LYRIE_FEISHU_APP_SECRET'], policyKey: 'LYRIE_FEISHU_DM_POLICY' },
  { name: 'rocketchat', enableKeys: ['LYRIE_ROCKETCHAT_URL', 'LYRIE_ROCKETCHAT_USER_ID', 'LYRIE_ROCKETCHAT_TOKEN'], policyKey: 'LYRIE_ROCKETCHAT_DM_POLICY' },
];

const VALID_POLICIES = new Set(['open', 'pairing', 'closed']);

function hasList(config: ParsedConfig, key: string): boolean {
  const v = envString(config, key);
  return !!v && v.split(',').some(s => s.trim() !== '');
}

export const ly003 = defineCheck({
  id: 'LY-003',
  name: 'DM Policy Open on Live Channel',
  category: 'lyrie',
  severity: 'critical',
  description: 'Detect gateway channels that are enabled (e.g. LYRIE_TELEGRAM_TOKEN, LYRIE_DISCORD_TOKEN, LYRIE_SLACK_BOT_TOKEN) while LYRIE_<CHANNEL>_DM_POLICY is unset, "open" or invalid — Lyrie then forwards every sender to the agent. Only Telegram enforces LYRIE_TELEGRAM_USERS/_CHATS on its own; for every other channel the LYRIE_<CHANNEL>_USERS allowlist applies only under the pairing or closed policy.',
  supportedAgents: ['lyrie'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    // judged on the merged layers: a policy or allowlist in .env.local
    // governs a token in .env
    for (const config of lyrieMergedEnvs(ctx.configs)) {
      for (const ch of CHANNELS) {
        if (!ch.enableKeys.every(k => isConfigured(envString(config, k)))) continue;

        const raw = envString(config, ch.policyKey);
        const policy = raw?.toLowerCase();
        if (policy === 'pairing' || policy === 'closed') continue;
        if (ch.selfEnforcedAllowlist?.some(k => hasList(config, k))) continue;

        const state = !policy
          ? 'unset (defaults to open)'
          : VALID_POLICIES.has(policy)
            ? '"open"'
            : `"${raw}" (invalid — ignored, behaves as open)`;
        const allowlistNote = ch.selfEnforcedAllowlist
          ? ` and no ${ch.selfEnforcedAllowlist.join('/')} allowlist`
          : '';
        evidence.push({
          file: envFile(config, raw === undefined ? ch.enableKeys[0] : ch.policyKey),
          snippet: `${ch.policyKey}=${raw ?? ''}`,
          detail: `Channel "${ch.name}" is enabled with ${ch.policyKey} ${state}${allowlistNote} — any sender who reaches the bot can drive the agent`,
        });
      }
    }
    return h.fromEvidence(evidence, {
      passed: 'All enabled channels use the pairing/closed DM policy or an enforced allowlist',
      failed: count => `${count} enabled channel(s) accept messages from any sender`,
      fixDescription: 'For each affected channel set LYRIE_<CHANNEL>_DM_POLICY=pairing (approve senders with `bun run pairing approve <channel> <code>` in the checkout) or =closed with LYRIE_<CHANNEL>_USERS',
    });
  },
});
