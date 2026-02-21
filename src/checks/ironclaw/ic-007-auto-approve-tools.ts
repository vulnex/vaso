import type { CheckModule, ScanContext, CheckResult } from '../../core/types.js';
import { getNestedValue } from '../../core/utils.js';

export const ic007: CheckModule = {
  id: 'IC-007',
  name: 'Auto-Approve Tools Enabled',
  category: 'ironclaw',
  severity: 'critical',
  description: 'Check if AGENT_AUTO_APPROVE_TOOLS is enabled, bypassing all tool approval prompts',
  supportedAgents: ['ironclaw'],

  async run(ctx: ScanContext): Promise<CheckResult> {
    const evidence = [];

    for (const config of ctx.configs) {
      const autoApprove =
        (config.data.AGENT_AUTO_APPROVE_TOOLS as string | undefined) ??
        (getNestedValue(config.data, 'agent.auto_approve_tools') as string | boolean | undefined) ??
        (getNestedValue(config.data, 'agent.autoApproveTools') as string | boolean | undefined);

      if (autoApprove === true || autoApprove === 'true') {
        evidence.push({
          file: config.filePath,
          detail: 'AGENT_AUTO_APPROVE_TOOLS=true — all tool executions bypass approval prompts',
        });
      }
    }

    return {
      id: 'IC-007',
      name: 'Auto-Approve Tools Enabled',
      category: 'ironclaw',
      severity: 'critical',
      passed: evidence.length === 0,
      message: evidence.length === 0
        ? 'Tool auto-approval is not enabled'
        : 'Tool auto-approval is enabled — all tool executions bypass user confirmation',
      evidence: evidence.length > 0 ? evidence : undefined,
      fixable: true,
      fixDescription: 'Set AGENT_AUTO_APPROVE_TOOLS=false in .env or agent.auto_approve_tools=false in config.toml',
    };
  },
};
