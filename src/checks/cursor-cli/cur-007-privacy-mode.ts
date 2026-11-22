import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

export const cur007 = defineCheck({
  id: 'CUR-007',
  name: 'Cursor Privacy Mode Disabled',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Detect when privacyCache shows ghostMode=false or privacyMode allowing training (3/4; 1 no-storage and 2 no-training are private)',
  supportedAgents: ['cursor-cli'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      const privacy = config.data.privacyCache as Record<string, unknown> | undefined;
      if (!privacy || typeof privacy !== 'object') continue;

      if (privacy.ghostMode === false) {
        evidence.push({
          file: config.filePath,
          snippet: 'privacyCache.ghostMode = false',
          detail: 'Ghost mode off — Cursor may store and use code/prompts beyond the active session',
        });
      }
      // Cursor's PrivacyMode enum (agent.v1): 0 UNSPECIFIED, 1 NO_STORAGE,
      // 2 NO_TRAINING (Privacy Mode), 3 USAGE_DATA_TRAINING_ALLOWED,
      // 4 USAGE_CODEBASE_TRAINING_ALLOWED. 1 and 2 both keep code out of training.
      const mode = privacy.privacyMode;
      if (typeof mode === 'number' && mode !== 1 && mode !== 2) {
        const training = mode === 3 || mode === 4;
        evidence.push({
          file: config.filePath,
          snippet: `privacyCache.privacyMode = ${mode}`,
          detail: training
            ? `Privacy mode off (${mode === 3 ? 'usage data' : 'usage data and codebase'} training allowed) — code and prompts may be used for training`
            : mode === 0
              ? 'Privacy mode unspecified — Cursor falls back to no-training; confirm Privacy Mode in Cursor settings'
              : `Unrecognised privacy mode ${mode} — confirm Privacy Mode in Cursor settings`,
          ...(training ? {} : { mitigated: true }),
        });
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'Cursor privacy mode is enabled (ZDR active)',
      failed: (n) => `Cursor privacy mode is weakened (${n} signal(s))`,
      fixDescription: 'Enable Privacy Mode in Cursor settings — ensures Zero Data Retention with model providers',
    });
  },
});
