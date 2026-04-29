import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

export const opc011 = defineCheck({
  id: 'OPC-011',
  name: 'OpenCode Snapshot Disabled',
  category: 'coding-agent',
  severity: 'info',
  description: 'Detect when snapshot is disabled — file rollback after a destructive edit is not available',
  supportedAgents: ['opencode'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      if (config.data.snapshot === false) {
        evidence.push({
          file: config.filePath,
          snippet: 'snapshot = false',
          detail: 'Snapshot disabled — there is no rollback path if the agent makes a destructive edit',
        });
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'OpenCode snapshot is enabled (default)',
      failed: () => 'OpenCode snapshot is disabled — no rollback after destructive edits',
      fixDescription: 'Remove "snapshot": false from opencode.json (snapshot defaults to true)',
    });
  },
});
