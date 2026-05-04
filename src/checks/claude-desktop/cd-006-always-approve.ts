import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

const APPROVAL_KEYS = ['alwaysApprove', 'autoApprove', 'autoApproveTools'];

function collectApprovals(obj: Record<string, unknown>): string[] {
  for (const key of APPROVAL_KEYS) {
    const v = obj[key];
    if (Array.isArray(v)) return v.filter((s): s is string => typeof s === 'string');
    if (v === true) return ['*'];
  }
  return [];
}

export const cd006 = defineCheck({
  id: 'CD-006',
  name: 'Always-Approve MCP Tools',
  category: 'coding-agent',
  severity: 'critical',
  description: 'Detect alwaysApprove / autoApprove configuration that bypasses tool confirmation prompts',
  supportedAgents: ['claude-desktop'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      const top = collectApprovals(config.data);
      if (top.length > 0) {
        evidence.push({
          file: config.filePath,
          snippet: `top-level alwaysApprove = ${JSON.stringify(top)}`,
          detail: 'Global auto-approve list — every MCP tool runs without user confirmation',
        });
      }

      const mcpServers = config.data.mcpServers as Record<string, unknown> | undefined;
      if (!mcpServers || typeof mcpServers !== 'object') continue;
      for (const [name, srv] of Object.entries(mcpServers)) {
        if (!srv || typeof srv !== 'object') continue;
        const tools = collectApprovals(srv as Record<string, unknown>);
        if (tools.length === 0) continue;

        const broad = tools.includes('*') || tools.length >= 5;
        evidence.push({
          file: config.filePath,
          snippet: `mcpServers.${name}.alwaysApprove = ${JSON.stringify(tools)}`,
          detail: broad
            ? 'Server has broad auto-approve — prompt-injection tool calls execute without user confirmation'
            : `Server auto-approves ${tools.length} tool(s) — narrow the list and re-evaluate each entry`,
        });
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'No always-approve auto-trust configured for MCP tools',
      failed: (n) => `Found ${n} alwaysApprove configuration(s) — confirmation prompts bypassed`,
      fixDescription: 'Remove alwaysApprove entries; require explicit confirmation per tool call',
    });
  },
});
