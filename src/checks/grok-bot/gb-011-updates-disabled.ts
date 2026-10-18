import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { GROK_BOT_APP_LINUX, GROK_BOT_APT_SOURCE } from '../../adapters/grok-bot.js';
import { envFlag, isOwnSession, settingsConfig } from './shared.js';

// deb822 field; the postinst rewrites the file on every upgrade but keeps it
const APT_DISABLED = /^Enabled:\s*(?:no|false|0)\s*$/im;

export const gb011 = defineCheck({
  id: 'GB-011',
  name: 'Grok Bot Updates Disabled',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Detect Grok Bot updates switched off — SAND_DISABLE_UPDATES=1, or the .deb\'s apt source (/etc/apt/sources.list.d/grok-bot.sources) set to Enabled: no — and an internal pre-release update track (updateTrackOverride: "dogfood")',
  supportedAgents: ['grok-bot'],

  async run(ctx, h) {
    const warning: Evidence[] = [];
    const info: Evidence[] = [];

    if (isOwnSession(ctx) && envFlag(ctx, 'SAND_DISABLE_UPDATES')) {
      // A .deb/.rpm install updates through the package manager, not the app
      const packageManaged = ctx.fs.platform === 'linux' && ctx.installation.appBundle === GROK_BOT_APP_LINUX;
      (packageManaged ? info : warning).push({
        file: '<process env>',
        snippet: 'SAND_DISABLE_UPDATES=1',
        detail: packageManaged
          ? 'The app\'s own updater is off — this .deb install still updates through apt'
          : 'The app never checks for updates — security fixes stop arriving',
      });
    }
    if (ctx.fs.platform === 'linux') {
      try {
        const source = await ctx.fs.readFile(GROK_BOT_APT_SOURCE);
        if (APT_DISABLED.test(source)) {
          warning.push({ file: GROK_BOT_APT_SOURCE, snippet: 'Enabled: no', detail: 'The .deb updates only through apt — with its source disabled, apt upgrade never installs a new version' });
        }
      } catch {
        // AppImage/.rpm installs, or not collected
      }
    }
    // "nightly" is coerced to stable by 0.71.2, so only "dogfood" leaves
    // stable — and only while Grok Bot's server unlocks internal tracks for
    // the account (otherwise the app resets it to stable). A .deb/.rpm under
    // /opt is updated by the package manager, which ignores the track.
    const config = settingsConfig(ctx);
    if (config?.data.updateTrackOverride === 'dogfood') {
      const packageManaged = ctx.fs.platform === 'linux' && ctx.installation.appBundle === GROK_BOT_APP_LINUX;
      info.push({
        file: config.filePath,
        snippet: 'updateTrackOverride: "dogfood"',
        detail: packageManaged
          ? 'Ignored: this install is updated by the package manager, which has no update tracks'
          : 'Follows the internal pre-release track while Grok Bot\'s server unlocks it for the account',
        mitigated: packageManaged || undefined,
      });
    }

    return h.fromEvidence([...warning, ...info], {
      passed: 'Grok Bot updates are enabled on the stable track',
      failed: (n) => `Found ${n} Grok Bot update setting(s) worth reviewing`,
      severity: warning.length > 0 || info.length === 0 ? undefined : 'info',
      fixDescription: 'Unset SAND_DISABLE_UPDATES and remove "Enabled: no" from /etc/apt/sources.list.d/grok-bot.sources (then apt update && apt upgrade grok-bot)',
    });
  },
});
