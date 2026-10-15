import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

export const ghc005 = defineCheck({
  id: 'GHC-005',
  name: 'Copilot CLI Prerelease Update Channel',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Surface when autoUpdatesChannel (or legacy updateChannel) is set to "prerelease" — less-vetted code paths',
  supportedAgents: ['copilot-cli'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      if (!config.filePath.endsWith('settings.json')) continue;
      // `autoUpdatesChannel` is the documented key (CLI config-dir reference);
      // `updateChannel` is kept for older configs
      const key = config.data.autoUpdatesChannel !== undefined ? 'autoUpdatesChannel' : 'updateChannel';
      const channel = config.data[key];
      if (typeof channel === 'string' && channel.toLowerCase() === 'prerelease') {
        evidence.push({
          file: config.filePath,
          snippet: `${key} = "${channel}"`,
          detail: 'Auto-updates pull prerelease builds — these may include features not yet vetted for production',
        });
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'Copilot CLI update channel is stable',
      failed: () => 'Copilot CLI update channel is "prerelease"',
      fixDescription: 'Set autoUpdatesChannel: "stable" in ~/.copilot/settings.json unless you intentionally test prereleases',
    });
  },
});
