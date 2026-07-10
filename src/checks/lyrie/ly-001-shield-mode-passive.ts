import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { fixFirstConfig } from '../../remediation/config-writer.js';

export const ly001 = defineCheck({
  id: 'LY-001',
  name: 'Lyrie Shield Mode Passive',
  category: 'lyrie',
  severity: 'critical',
  description: 'Detect LYRIE_SHIELD_MODE=passive — Shield logs threats but does not block them, leaving Layer-1 enforcement effectively disabled.',
  supportedAgents: ['lyrie'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    for (const config of ctx.configs) {
      const mode = config.data.LYRIE_SHIELD_MODE as string | undefined;
      if (mode === 'passive') {
        evidence.push({
          file: config.filePath,
          detail: 'LYRIE_SHIELD_MODE=passive — threats are logged but not blocked',
        });
      }
    }
    return h.fromEvidence(evidence, {
      passed: 'Shield mode is active or strict',
      failed: () => 'Shield mode is passive — Layer-1 enforcement is disabled',
      fixable: true,
      fixDescription: 'Set LYRIE_SHIELD_MODE=active in .env',
    });
  },

  async fix(ctx) {
    return fixFirstConfig(ctx.configs, {
      checkId: 'LY-001',
      env: 'LYRIE_SHIELD_MODE',
      value: 'active',
      message: 'Set LYRIE_SHIELD_MODE=active',
      noConfigMessage: 'No .env file found',
    });
  },
});
