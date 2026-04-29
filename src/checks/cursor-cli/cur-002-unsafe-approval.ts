import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

const UNSAFE_MODES = new Set(['yolo', 'auto', 'run-everything', 'force', 'auto-everything']);

export const cur002 = defineCheck({
  id: 'CUR-002',
  name: 'Cursor Unsafe Approval Mode',
  category: 'coding-agent',
  severity: 'critical',
  description: 'Detect approvalMode set to a value that auto-approves all tool calls',
  supportedAgents: ['cursor-cli'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      const mode = config.data.approvalMode;
      if (typeof mode === 'string' && UNSAFE_MODES.has(mode.toLowerCase())) {
        evidence.push({
          file: config.filePath,
          snippet: `approvalMode = "${mode}"`,
          detail: 'Cursor will execute tool calls (including shell commands) without per-call confirmation',
        });
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'Cursor approval mode requires explicit allow rules or per-call confirmation',
      failed: () => 'Cursor approvalMode auto-approves every tool call',
      fixDescription: 'Set approvalMode to "default" or "allowlist" in ~/.cursor/cli-config.json',
    });
  },
});
