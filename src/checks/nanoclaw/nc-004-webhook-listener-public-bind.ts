import { join } from 'node:path';
import { defineCheck } from '../../core/check-builder.js';
import { checkoutDir, checkoutEnv } from './shared.js';
import { compareVersions } from '../../core/semver.js';
import type { ScanContext } from '../../core/types.js';

/**
 * First release whose webhook server binds WEBHOOK_HOST, default 127.0.0.1
 * (upstream 8a91aadb, #4185); earlier ones hardcode listen(port, '0.0.0.0').
 */
const LOOPBACK_DEFAULT_SINCE = '2026.10.1-rc.2';
const LOOPBACK = /^(?:127(?:\.\d{1,3}){3}|::1|\[::1\]|localhost)$/i;

/**
 * The address the webhook server binds: WEBHOOK_HOST from the checkout's
 * .env, else the release default — read from src/config.ts when the source
 * is readable (a local scan), else decided by the checkout's version.
 */
async function webhookHost(ctx: ScanContext, checkout: string, env: Record<string, unknown>): Promise<{ host: string; from: string }> {
  if (typeof env.WEBHOOK_HOST === 'string' && env.WEBHOOK_HOST.trim()) return { host: env.WEBHOOK_HOST.trim(), from: 'WEBHOOK_HOST' };
  try {
    const config = await ctx.fs.readFile(join(checkout, 'src', 'config.ts'));
    return /\bWEBHOOK_HOST\b/.test(config)
      ? { host: '127.0.0.1', from: 'default' }
      : { host: '0.0.0.0', from: 'hardcoded' };
  } catch {
    // source not collected (remote snapshot) — the version decides
  }
  const version = ctx.installation.version;
  return version && compareVersions(version, LOOPBACK_DEFAULT_SINCE) >= 0
    ? { host: '127.0.0.1', from: 'default' }
    : { host: '0.0.0.0', from: 'hardcoded' };
}

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
  description: 'Detect installed webhook-mode channels (Slack without Socket Mode, Teams, GitHub, Linear, Google Chat, Webex, WhatsApp Cloud, Mattermost, Resend): NanoClaw then serves /webhook/* on WEBHOOK_HOST:WEBHOOK_PORT, relying solely on each platform\'s request signature. Releases before 2026.10.1-rc.2 hardcode 0.0.0.0; later ones default to 127.0.0.1, so only a non-loopback WEBHOOK_HOST is reported there.',
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

    if (webhook.length === 0) return h.passed('No webhook-mode channel installed; NanoClaw opens no network listener');

    const { host, from } = await webhookHost(ctx, checkout, env);
    if (LOOPBACK.test(host)) {
      return h.passed(`Webhook server for ${webhook.join(', ')} listens on ${host}:${port} (${from === 'WEBHOOK_HOST' ? 'WEBHOOK_HOST' : 'release default'}) — loopback only`);
    }
    const all = host === '0.0.0.0' || host === '::' || host === '[::]';
    const evidence = [{
      file: from === 'WEBHOOK_HOST' ? checkoutEnv(ctx).file ?? barrel : barrel,
      detail: `Webhook channel${webhook.length === 1 ? '' : 's'} ${webhook.join(', ')} → listener on ${host}:${port} (/webhook/${webhook.join(', /webhook/')})${from === 'WEBHOOK_HOST' ? ' set by WEBHOOK_HOST' : from === 'hardcoded' ? ' (bind address hardcoded in this release)' : ''}, ${all ? 'reachable from every interface' : 'reachable beyond this host'}`,
    }];

    return h.fromEvidence(evidence, {
      passed: 'No webhook-mode channel installed; NanoClaw opens no network listener',
      failed: () => all
        ? `NanoClaw webhook server listens on all interfaces (port ${port})`
        : `NanoClaw webhook server listens on ${host} (port ${port}), beyond loopback`,
      fixable: false,
      fixDescription: `Set WEBHOOK_HOST=127.0.0.1 in .env (releases from ${LOOPBACK_DEFAULT_SINCE}) and publish it through a TLS reverse proxy/tunnel, or firewall port ${port} to the platform's source ranges; prefer Socket Mode for Slack (set SLACK_APP_TOKEN)`,
    });
  },
});
