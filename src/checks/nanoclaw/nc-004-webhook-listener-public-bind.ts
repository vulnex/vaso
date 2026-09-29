import { join } from 'node:path';
import { defineCheck } from '../../core/check-builder.js';
import { checkoutDir, checkoutEnv } from './shared.js';

/**
 * Channel modules installed by the add-<channel> skills that receive events
 * over NanoClaw's shared webhook server. Chat SDK adapters that poll
 * (Telegram), hold a gateway connection (Discord) or talk to a local bridge
 * (Signal, WhatsApp/Baileys, iMessage, Matrix, WeChat, …) never register a
 * route. Slack is webhook-mode unless SLACK_APP_TOKEN enables Socket Mode.
 */
const WEBHOOK_CHANNELS = new Set([
  'slack', 'teams', 'github', 'linear', 'gchat', 'webex', 'whatsapp-cloud', 'mattermost', 'resend',
]);

/** `import './slack.js';` lines in src/channels/index.ts (comments ignored). */
export function installedChannels(source: string): string[] {
  const out: string[] = [];
  for (const line of source.split('\n')) {
    const m = /^\s*import\s+['"]\.\/([a-z0-9-]+)(?:\.js|\.ts)?['"]\s*;?\s*$/.exec(line);
    if (m) out.push(m[1]);
  }
  return out;
}

export const nc004 = defineCheck({
  id: 'NC-004',
  name: 'Webhook Listener Bound to All Interfaces',
  category: 'nanoclaw',
  severity: 'warning',
  description: 'Detect installed webhook-mode channels (Slack without Socket Mode, Teams, GitHub, Linear, Google Chat, Webex, WhatsApp Cloud, Mattermost, Resend): NanoClaw then serves /webhook/* on 0.0.0.0:WEBHOOK_PORT (the bind address is hardcoded), relying solely on each platform\'s request signature.',
  supportedAgents: ['nanoclaw'],

  async run(ctx, h) {
    const checkout = checkoutDir(ctx);
    if (!checkout) return h.passed('No NanoClaw checkout located');

    const barrel = join(checkout, 'src', 'channels', 'index.ts');
    let source: string;
    try {
      source = await ctx.fs.readFile(barrel);
    } catch {
      return h.passed('Channel barrel not readable; no webhook channels detected');
    }

    const env = checkoutEnv(ctx).data;
    const port = typeof env.WEBHOOK_PORT === 'string' && env.WEBHOOK_PORT.trim() ? env.WEBHOOK_PORT.trim() : '3000';
    const slackSocketMode = typeof env.SLACK_APP_TOKEN === 'string' && env.SLACK_APP_TOKEN.trim() !== '';

    const webhook = installedChannels(source)
      .filter(c => WEBHOOK_CHANNELS.has(c))
      .filter(c => !(c === 'slack' && slackSocketMode));

    const evidence = webhook.length === 0 ? [] : [{
      file: barrel,
      detail: `Webhook channel${webhook.length === 1 ? '' : 's'} ${webhook.join(', ')} → listener on 0.0.0.0:${port} (/webhook/${webhook.join(', /webhook/')}), reachable from every interface`,
    }];

    return h.fromEvidence(evidence, {
      passed: 'No webhook-mode channel installed; NanoClaw opens no network listener',
      failed: () => `NanoClaw webhook server listens on all interfaces (port ${port})`,
      fixable: false,
      fixDescription: `Firewall port ${port} to the platform's source ranges or expose it only through a TLS reverse proxy/tunnel; prefer Socket Mode for Slack (set SLACK_APP_TOKEN)`,
    });
  },
});
