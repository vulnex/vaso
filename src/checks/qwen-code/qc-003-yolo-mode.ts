import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { markUntrustedWorkspace } from '../../adapters/folder-trust.js';
import { qwenWorkspaceTrusted } from '../../adapters/qwen-code.js';
import { approvalMode } from './approval-mode.js';

const DANGEROUS_MODES = new Set(['yolo']);

export const qc003 = defineCheck({
  id: 'QC-003',
  name: 'Qwen YOLO Approval Mode',
  category: 'coding-agent',
  severity: 'critical',
  description: 'Detect tools.approvalMode (or legacy top-level approvalMode) set to "yolo" — auto-approves every tool call',
  supportedAgents: ['qwen-code'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      const found = approvalMode(config);
      if (found && DANGEROUS_MODES.has(found.mode.toLowerCase())) {
        evidence.push({
          file: config.filePath,
          snippet: `${found.key} = "${found.mode}"`,
          detail: 'Qwen will execute every tool — including shell commands — without prompting',
        });
      }
    }

    await markUntrustedWorkspace(ctx, evidence, qwenWorkspaceTrusted);

    return h.fromEvidence(evidence, {
      passed: 'Qwen approval mode is not yolo',
      failed: () => 'Qwen approvalMode is set to yolo — every tool auto-approves',
      fixDescription: 'Set tools.approvalMode to "default" (or "plan" for read-only) in ~/.qwen/settings.json',
    });
  },
});
