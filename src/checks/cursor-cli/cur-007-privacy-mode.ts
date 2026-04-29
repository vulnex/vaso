import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

export const cur007 = defineCheck({
  id: 'CUR-007',
  name: 'Cursor Privacy Mode Disabled',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Detect when privacyCache shows ghostMode=false or privacyMode != 1 (training data may be retained)',
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
      if (typeof privacy.privacyMode === 'number' && privacy.privacyMode !== 1) {
        evidence.push({
          file: config.filePath,
          snippet: `privacyCache.privacyMode = ${privacy.privacyMode}`,
          detail: 'Privacy mode disabled (1 = on) — code may be sent to model providers for training',
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
