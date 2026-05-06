import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { CODING_AGENTS } from '../../core/types.js';
import { getNestedValue } from '../../core/utils.js';

export const pol001 = defineCheck({
  id: 'POL-001',
  name: 'Exec Approval Required',
  category: 'policy',
  severity: 'warning',
  description: 'Verify tool execution requires user approval and is not auto-approved',
  excludedAgents: CODING_AGENTS,

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      const execApproval = getNestedValue(config.data, 'execApproval') ??
                           getNestedValue(config.data, 'tool_approval') ??
                           getNestedValue(config.data, 'security.execApproval') ??
                           getNestedValue(config.data, 'security.tool_approval');

      const autoApprove = getNestedValue(config.data, 'auto_approve') ??
                          getNestedValue(config.data, 'autoApprove') ??
                          getNestedValue(config.data, 'security.autoApprove') ??
                          getNestedValue(config.data, 'tools.autoApprove');

      if (execApproval === false || execApproval === 'disabled' || execApproval === 'off') {
        evidence.push({
          file: config.filePath,
          detail: `Execution approval is disabled: ${String(execApproval)}`,
        });
      }

      if (autoApprove === true || autoApprove === 'all' || autoApprove === '*') {
        evidence.push({
          file: config.filePath,
          detail: `Tools are auto-approved: ${String(autoApprove)}`,
        });
      }
    }

    const envAutoApprove = ctx.fs.getEnv('AGENT_AUTO_APPROVE_TOOLS');
    if (envAutoApprove === 'true' || envAutoApprove === '1' || envAutoApprove === 'all') {
      evidence.push({
        file: 'environment',
        detail: `AGENT_AUTO_APPROVE_TOOLS=${envAutoApprove}`,
      });
    }

    return h.fromEvidence(evidence, {
      passed: 'Tool execution approval is properly configured',
      failed: (n) => `Found ${n} issue(s) with execution approval policy`,
    });
  },
});
