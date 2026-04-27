import { defineCheck } from '../../core/check-builder.js';
import { updateEnvFile, updateTomlFile } from '../../remediation/config-writer.js';
import { getNestedValue } from '../../core/utils.js';

export const ic007 = defineCheck({
  id: 'IC-007',
  name: 'Auto-Approve Tools Enabled',
  category: 'ironclaw',
  severity: 'critical',
  description: 'Check if AGENT_AUTO_APPROVE_TOOLS is enabled, bypassing all tool approval prompts',
  supportedAgents: ['ironclaw'],

  async run(ctx, h) {
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

    return h.fromEvidence(evidence, {
      passed: 'Tool auto-approval is not enabled',
      failed: () => 'Tool auto-approval is enabled — all tool executions bypass user confirmation',
      fixable: true,
      fixDescription: 'Set AGENT_AUTO_APPROVE_TOOLS=false in .env or agent.auto_approve_tools=false in config.toml',
    });
  },

  async fix(ctx) {
    for (const config of ctx.configs) {
      if (config.format === 'env') {
        await updateEnvFile(config.filePath, 'AGENT_AUTO_APPROVE_TOOLS', 'false');
        return { checkId: 'IC-007', applied: true, message: 'Set AGENT_AUTO_APPROVE_TOOLS=false' };
      }
      if (config.format === 'toml') {
        await updateTomlFile(config.filePath, 'agent.auto_approve_tools', false);
        return { checkId: 'IC-007', applied: true, message: 'Set AGENT_AUTO_APPROVE_TOOLS=false' };
      }
    }
    return { checkId: 'IC-007', applied: false, message: 'No compatible config file found' };
  },
});
