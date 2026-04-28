import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { updateEnvFile } from '../../remediation/config-writer.js';

export const ly009 = defineCheck({
  id: 'LY-009',
  name: 'Lyrie Local Dry-Run Enabled',
  category: 'lyrie',
  severity: 'warning',
  description: 'Detect LYRIE_LOCAL_DRY_RUN=true — backend returns empty SARIF without running Lyrie. Operators may believe scans are running when they are not.',
  supportedAgents: ['lyrie'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    for (const config of ctx.configs) {
      const dryRun = config.data.LYRIE_LOCAL_DRY_RUN as string | undefined;
      if (dryRun === 'true' || dryRun === '1') {
        evidence.push({
          file: config.filePath,
          detail: 'LYRIE_LOCAL_DRY_RUN=true — Lyrie reports no findings without scanning',
        });
      }
    }
    return h.fromEvidence(evidence, {
      passed: 'Dry-run mode is not enabled',
      failed: () => 'Dry-run mode is on — Lyrie returns empty SARIF without running',
      fixable: true,
      fixDescription: 'Remove LYRIE_LOCAL_DRY_RUN from .env (or set it to false)',
    });
  },

  async fix(ctx) {
    for (const config of ctx.configs) {
      if (config.format === 'env' && 'LYRIE_LOCAL_DRY_RUN' in config.data) {
        await updateEnvFile(config.filePath, 'LYRIE_LOCAL_DRY_RUN', 'false');
        return { checkId: 'LY-009', applied: true, message: 'Set LYRIE_LOCAL_DRY_RUN=false' };
      }
    }
    return { checkId: 'LY-009', applied: false, message: 'No .env file found' };
  },
});
