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
  // OpenClaw's exec policy is tools.exec.mode (CFG-005); none of these keys
  // exist in its schema, which rejects unknown keys
  excludedAgents: [...CODING_AGENTS, 'openclaw'],

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

    // AGENT_AUTO_APPROVE_TOOLS is IronClaw 0.x's own variable (IC-007 reads it
    // from the agent's .env); VASO's environment says nothing about another agent

    return h.fromEvidence(evidence, {
      passed: 'Tool execution approval is properly configured',
      failed: (n) => `Found ${n} issue(s) with execution approval policy`,
    });
  },
});
