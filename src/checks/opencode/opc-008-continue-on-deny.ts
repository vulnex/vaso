import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { getNestedValue } from '../../core/utils.js';

export const opc008 = defineCheck({
  id: 'OPC-008',
  name: 'OpenCode Continue Loop on Deny',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Detect when experimental.continue_loop_on_deny is enabled — the agent retries after a user deny',
  supportedAgents: ['opencode'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      const flag = getNestedValue(config.data, 'experimental.continue_loop_on_deny');
      if (flag === true) {
        evidence.push({
          file: config.filePath,
          snippet: 'experimental.continue_loop_on_deny = true',
          detail: 'Agent loop continues after the user denies a tool — denial no longer halts execution',
        });
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'OpenCode halts the loop when a user denies a tool',
      failed: () => 'OpenCode is configured to continue running after a user denies a tool',
      fixDescription: 'Remove experimental.continue_loop_on_deny from opencode.json or set it to false',
    });
  },
});
