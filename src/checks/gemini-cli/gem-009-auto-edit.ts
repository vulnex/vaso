import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

export const gem009 = defineCheck({
  id: 'GEM-009',
  name: 'Gemini Auto-Approve Edit Mode',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Detect when general.defaultApprovalMode is (or legacy tools.approvalMode) is set to "auto_edit" — file edits run without prompting',
  supportedAgents: ['gemini-cli'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      const general = config.data.general as Record<string, unknown> | undefined;
      const tools = config.data.tools as Record<string, unknown> | undefined;
      // Legacy `tools.approvalMode` is migrated to general.defaultApprovalMode
      // at load time when the latter is unset (settings.ts
      // migrateDeprecatedSettings), so it still takes effect.
      const [key, mode] = general?.defaultApprovalMode !== undefined
        ? ['general.defaultApprovalMode', general.defaultApprovalMode]
        : ['tools.approvalMode', tools?.approvalMode];
      if (typeof mode === 'string' && mode.toLowerCase() === 'auto_edit') {
        evidence.push({
          file: config.filePath,
          snippet: `${key} = "${mode}"`,
          detail: 'Edit tools (file write, patch) auto-approve without per-call prompt',
        });
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'Gemini default approval mode requires confirmation',
      failed: () => 'Gemini default approval mode auto-approves edits',
      fixDescription: 'Set general.defaultApprovalMode to "default" (or "plan" for read-only) in ~/.gemini/settings.json',
    });
  },
});
