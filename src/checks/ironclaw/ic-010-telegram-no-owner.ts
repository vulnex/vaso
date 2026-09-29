import { join } from 'node:path';
import { defineCheck } from '../../core/check-builder.js';
import { isLegacy, isLegacyUnused, legacyEnv, str } from './layout.js';

/*
 * 0.x only. Telegram is a WASM channel installed into
 * `$WASM_CHANNELS_DIR` (default ~/.ironclaw/channels); its bot token lives in
 * the encrypted secrets store, not in env (TELEGRAM_TOKEN, which this check
 * used to read, never existed). TELEGRAM_OWNER_ID (env) pins the bot to one
 * Telegram user; without it (and without an owner id in the settings DB) the
 * bot answers anyone who completes DM pairing.
 * 1.x configures Telegram as a WebUI extension — its `[telegram]` config
 * section is retired and inert, so there is nothing static to evaluate.
 */

export const ic010 = defineCheck({
  id: 'IC-010',
  name: 'Telegram Channel Without Owner ID (0.x)',
  category: 'ironclaw',
  severity: 'warning',
  description: 'Check if the IronClaw 0.x Telegram WASM channel is installed without TELEGRAM_OWNER_ID pinning it to one user',
  supportedAgents: ['ironclaw'],

  async run(ctx, h) {
    if (!isLegacy(ctx)) return h.passed('Not applicable to IronClaw 1.x (Telegram is a WebUI extension)');
    if (isLegacyUnused(ctx)) return h.passed('0.x configuration is not used by the installed IronClaw 1.x binary');

    const env = legacyEnv(ctx);
    const channelsDir = str(env?.data?.WASM_CHANNELS_DIR) || join(ctx.installation.installDir, 'channels');
    let installed: string | undefined;
    try {
      installed = (await ctx.fs.readdir(channelsDir)).find(n => /telegram/i.test(n));
    } catch {
      installed = undefined;
    }
    if (!installed) return h.passed('Telegram channel is not installed');

    const owner = str(env?.data?.TELEGRAM_OWNER_ID);
    if (owner) return h.passed('Telegram channel is pinned to an owner (TELEGRAM_OWNER_ID)');

    return h.result({
      passed: false,
      message: 'Telegram channel installed without an owner ID — any Telegram user can reach the agent via DM pairing',
      evidence: [{
        file: join(channelsDir, installed),
        detail: 'TELEGRAM_OWNER_ID is not set in .env (an owner id set via the settings database is not visible to static scanning)',
      }],
      fixDescription: 'Set TELEGRAM_OWNER_ID=<your numeric Telegram user id> in ~/.ironclaw/.env',
    });
  },
});
