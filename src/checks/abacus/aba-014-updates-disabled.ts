import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { isProjectInstall, settingsConfigs } from './shared.js';

// Release channels other than the default "latest" ship pre-release builds.
const PRERELEASE_CHANNELS = /^(?:next|canary|rc|beta|alpha|dev|nightly)$/i;

export const aba014 = defineCheck({
  id: 'ABA-014',
  name: 'Abacus.AI Updates Disabled or Pre-Release Channel',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Detect Abacus.AI autoUpdate: "off" (security fixes stop arriving) and an updateChannel or CODELLM_CHANNEL following pre-release builds (canary, next, rc)',
  supportedAgents: ['abacus'],

  async run(ctx, h) {
    // autoUpdate and updateChannel are user-scope settings; project files can't set them
    if (isProjectInstall(ctx)) {
      return h.passed('Update settings are user-level — evaluated on the user installation');
    }
    const warning: Evidence[] = [];
    const info: Evidence[] = [];

    for (const config of settingsConfigs(ctx.configs)) {
      const auto = config.data.autoUpdate;
      // The CLI maps legacy booleans: false/"no" → off
      if (auto === 'off' || auto === false || auto === 'no') {
        warning.push({ file: config.filePath, snippet: `autoUpdate: ${JSON.stringify(auto)}`, detail: 'Automatic updates are off — fixed security issues stay unpatched until a manual `abacusai upgrade`' });
      }
      const channel = config.data.updateChannel;
      if (typeof channel === 'string' && PRERELEASE_CHANNELS.test(channel.trim())) {
        info.push({ file: config.filePath, snippet: `updateChannel: "${channel}"`, detail: 'Follows a pre-release channel — builds ship before stable review' });
      }
    }
    const envChannel = ctx.fs.getEnv('CODELLM_CHANNEL');
    if (envChannel && PRERELEASE_CHANNELS.test(envChannel.trim())) {
      info.push({ file: '<process env>', snippet: `CODELLM_CHANNEL=${envChannel}`, detail: 'Follows a pre-release channel — builds ship before stable review' });
    }

    return h.fromEvidence([...warning, ...info], {
      passed: 'Abacus.AI follows the stable channel with automatic updates',
      failed: (n) => `Found ${n} Abacus.AI update setting(s) worth reviewing`,
      severity: warning.length > 0 ? undefined : 'info',
      fixDescription: 'Set autoUpdate to "auto" (or "prompt") and remove pre-release updateChannel / CODELLM_CHANNEL overrides',
    });
  },
});
