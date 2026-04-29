import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

export const opc012 = defineCheck({
  id: 'OPC-012',
  name: 'OpenCode Auto-Update Disabled',
  category: 'coding-agent',
  severity: 'info',
  description: 'Detect when OpenCode auto-update is disabled — binary may drift past security fixes',
  supportedAgents: ['opencode'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      if (config.data.autoupdate === false) {
        evidence.push({
          file: config.filePath,
          snippet: 'autoupdate = false',
          detail: 'Auto-update disabled — no notification when a security release ships',
        });
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'OpenCode auto-update is enabled or set to notify',
      failed: () => 'OpenCode auto-update is disabled',
      fixDescription: 'Remove "autoupdate": false from opencode.json, or set it to "notify"',
    });
  },
});
