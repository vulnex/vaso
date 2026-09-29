import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { fixFirstConfig } from '../../remediation/config-writer.js';
import { envTrue, lyrieEnvConfigs } from './env.js';

/** backends/factory.ts: dryRun = LYRIE_LOCAL_DRY_RUN === "1" || === "true". */
export const ly009 = defineCheck({
  id: 'LY-009',
  name: 'Lyrie Local Backend Dry-Run Enabled',
  category: 'lyrie',
  severity: 'warning',
  description: 'Detect LYRIE_LOCAL_DRY_RUN=true (or 1) — the local scan backend returns an empty SARIF without running Lyrie, so security scans report "no findings" without scanning anything.',
  supportedAgents: ['lyrie'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    for (const config of lyrieEnvConfigs(ctx.configs)) {
      if (envTrue(config, 'LYRIE_LOCAL_DRY_RUN', true)) {
        evidence.push({
          file: config.filePath,
          snippet: 'LYRIE_LOCAL_DRY_RUN=true',
          detail: 'Local backend in dry-run mode — scans return empty results without scanning',
        });
      }
    }
    return h.fromEvidence(evidence, {
      passed: 'Dry-run mode is not enabled',
      failed: () => 'Dry-run mode is on — Lyrie returns empty SARIF without scanning',
      fixable: true,
      fixDescription: 'Set LYRIE_LOCAL_DRY_RUN=false (or remove it) in the .env',
    });
  },

  async fix(ctx) {
    return fixFirstConfig(
      lyrieEnvConfigs(ctx.configs).filter(c => envTrue(c, 'LYRIE_LOCAL_DRY_RUN', true)),
      {
        checkId: 'LY-009',
        env: 'LYRIE_LOCAL_DRY_RUN',
        value: 'false',
        message: 'Set LYRIE_LOCAL_DRY_RUN=false',
        noConfigMessage: 'No .env with LYRIE_LOCAL_DRY_RUN enabled found',
      },
    );
  },
});
