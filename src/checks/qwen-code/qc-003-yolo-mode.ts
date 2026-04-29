import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

const DANGEROUS_MODES = new Set(['yolo']);

export const qc003 = defineCheck({
  id: 'QC-003',
  name: 'Qwen YOLO Approval Mode',
  category: 'coding-agent',
  severity: 'critical',
  description: 'Detect approvalMode set to "yolo" — auto-approves every tool call',
  supportedAgents: ['qwen-code'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      const mode = config.data.approvalMode;
      if (typeof mode === 'string' && DANGEROUS_MODES.has(mode.toLowerCase())) {
        evidence.push({
          file: config.filePath,
          snippet: `approvalMode = "${mode}"`,
          detail: 'Qwen will execute every tool — including shell commands — without prompting',
        });
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'Qwen approval mode is not yolo',
      failed: () => 'Qwen approvalMode is set to yolo — every tool auto-approves',
      fixDescription: 'Set approvalMode to "default" (or "plan" for read-only) in ~/.qwen/settings.json',
    });
  },
});
