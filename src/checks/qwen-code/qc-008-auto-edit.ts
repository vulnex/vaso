import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { markUntrustedWorkspace } from '../../adapters/folder-trust.js';
import { qwenWorkspaceTrusted } from '../../adapters/qwen-code.js';
import { approvalMode } from './approval-mode.js';

export const qc008 = defineCheck({
  id: 'QC-008',
  name: 'Qwen Auto-Edit Mode',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Detect tools.approvalMode (or legacy top-level approvalMode) set to "auto-edit" — file edits run without prompting (and report the classifier-reviewed "auto" mode as info)',
  supportedAgents: ['qwen-code'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      const found = approvalMode(config);
      const mode = found?.mode.toLowerCase();
      if (found && mode === 'auto-edit') {
        evidence.push({
          file: config.filePath,
          snippet: `${found.key} = "${found.mode}"`,
          detail: 'Edit tools (file write, patch) auto-approve without per-call prompt',
        });
      } else if (found && mode === 'auto') {
        // `auto`: an LLM classifier approves actions it judges safe and
        // blocks risky ones — the documented default (Qwen settings.md,
        // tools.approvalMode), so informational
        evidence.push({
          file: config.filePath,
          snippet: `${found.key} = "${found.mode}"`,
          detail: 'A model classifier, not you, approves tool calls it judges safe (the default mode) — deny rules still apply',
          mitigated: true,
        });
      }
    }

    await markUntrustedWorkspace(ctx, evidence, qwenWorkspaceTrusted);

    return h.fromEvidence(evidence, {
      passed: 'Qwen approval mode requires confirmation for edits',
      failed: () => evidence.every(e => e.mitigated)
        ? 'Qwen approvalMode is auto — a classifier approves tool calls it judges safe'
        : 'Qwen approvalMode is auto-edit — file changes run without prompting',
      fixDescription: 'Set tools.approvalMode to "default" (or "plan" for read-only) in ~/.qwen/settings.json',
    });
  },
});
