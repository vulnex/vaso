import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { approvalMode } from './approval-mode.js';

export const qc008 = defineCheck({
  id: 'QC-008',
  name: 'Qwen Auto-Edit Mode',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Detect tools.approvalMode (or legacy top-level approvalMode) set to "auto-edit" — file edits run without prompting',
  supportedAgents: ['qwen-code'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      const found = approvalMode(config);
      if (found && found.mode.toLowerCase() === 'auto-edit') {
        evidence.push({
          file: config.filePath,
          snippet: `${found.key} = "${found.mode}"`,
          detail: 'Edit tools (file write, patch) auto-approve without per-call prompt',
        });
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'Qwen approval mode requires confirmation for edits',
      failed: () => 'Qwen approvalMode is auto-edit — file changes run without prompting',
      fixDescription: 'Set tools.approvalMode to "default" (or "plan" for read-only) in ~/.qwen/settings.json',
    });
  },
});
