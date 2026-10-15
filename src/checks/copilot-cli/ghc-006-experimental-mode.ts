import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

export const ghc006 = defineCheck({
  id: 'GHC-006',
  name: 'Copilot CLI Experimental Mode Enabled',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Surface when experimental (or legacy experimentalMode) is enabled in settings.json',
  supportedAgents: ['copilot-cli'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      if (!config.filePath.endsWith('settings.json')) continue;
      // `experimental` is the documented key (CLI config-dir reference);
      // `experimentalMode` is kept for older configs
      const key = config.data.experimental === true ? 'experimental'
        : config.data.experimentalMode === true ? 'experimentalMode' : undefined;
      if (key) {
        evidence.push({
          file: config.filePath,
          snippet: `${key} = true`,
          detail: 'Unstable features may be active — behaviors and APIs not yet stable',
        });
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'Copilot CLI experimental mode is off',
      failed: () => 'Copilot CLI experimental mode is enabled',
      fixDescription: 'Set experimental: false in ~/.copilot/settings.json for production use',
    });
  },
});
