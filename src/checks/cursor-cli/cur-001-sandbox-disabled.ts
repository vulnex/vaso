import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

export const cur001 = defineCheck({
  id: 'CUR-001',
  name: 'Cursor Sandbox Disabled',
  category: 'coding-agent',
  severity: 'critical',
  description: 'Detect when sandbox.mode is set to "disabled" — tools run unsandboxed on the host',
  supportedAgents: ['cursor-cli'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      const sandbox = config.data.sandbox as Record<string, unknown> | undefined;
      if (!sandbox || typeof sandbox !== 'object') continue;
      const mode = sandbox.mode;
      if (typeof mode === 'string' && mode.toLowerCase() === 'disabled') {
        evidence.push({
          file: config.filePath,
          snippet: `sandbox.mode = "${mode}"`,
          detail: 'All Cursor tool calls execute on the host without sandboxing — relies entirely on permissions.allow as the only gate',
        });
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'Cursor sandbox is enabled',
      failed: () => 'Cursor sandbox is disabled — tools execute directly on the host',
      fixDescription: 'Set sandbox.mode to "enabled" (or another non-disabled mode) in ~/.cursor/cli-config.json',
    });
  },
});
