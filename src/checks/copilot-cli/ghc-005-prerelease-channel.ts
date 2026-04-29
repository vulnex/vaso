import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

export const ghc005 = defineCheck({
  id: 'GHC-005',
  name: 'Copilot CLI Prerelease Update Channel',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Surface when updateChannel is set to "prerelease" — less-vetted code paths',
  supportedAgents: ['copilot-cli'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      if (!config.filePath.endsWith('settings.json')) continue;
      const channel = config.data.updateChannel;
      if (typeof channel === 'string' && channel.toLowerCase() === 'prerelease') {
        evidence.push({
          file: config.filePath,
          snippet: `updateChannel = "${channel}"`,
          detail: 'Auto-updates pull prerelease builds — these may include features not yet vetted for production',
        });
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'Copilot CLI updateChannel is stable',
      failed: () => 'Copilot CLI updateChannel is "prerelease"',
      fixDescription: 'Set updateChannel: "stable" in ~/.copilot/settings.json unless you intentionally test prereleases',
    });
  },
});
