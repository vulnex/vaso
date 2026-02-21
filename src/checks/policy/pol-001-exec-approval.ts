import type { CheckModule, ScanContext, CheckResult, Evidence } from '../../core/types.js';
import { getNestedValue } from '../../core/utils.js';

export const pol001: CheckModule = {
  id: 'POL-001',
  name: 'Exec Approval Required',
  category: 'policy',
  severity: 'warning',
  description: 'Verify tool execution requires user approval and is not auto-approved',

  async run(ctx: ScanContext): Promise<CheckResult> {
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

    // Check environment variable
    const envAutoApprove = process.env['AGENT_AUTO_APPROVE_TOOLS'];
    if (envAutoApprove === 'true' || envAutoApprove === '1' || envAutoApprove === 'all') {
      evidence.push({
        file: 'environment',
        detail: `AGENT_AUTO_APPROVE_TOOLS=${envAutoApprove}`,
      });
    }

    return {
      id: 'POL-001',
      name: 'Exec Approval Required',
      category: 'policy',
      severity: 'warning',
      passed: evidence.length === 0,
      message: evidence.length === 0
        ? 'Tool execution approval is properly configured'
        : `Found ${evidence.length} issue(s) with execution approval policy`,
      evidence: evidence.length > 0 ? evidence : undefined,
    };
  },
};
