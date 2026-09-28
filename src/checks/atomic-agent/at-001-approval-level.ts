import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { getNestedValue } from '../../core/utils.js';
import { atomicConfigs } from './shared.js';

// agent.approvalLevel 1–5 (paranoid / workspace / home / operator / full trust).
// Level 4 stops asking for shell, skill scripts, process kill and network git;
// level 5 also auto-approves MCP tools, reads outside the working dir, email,
// and writes to config.json/.env. Legacy `approvalRequired: false` loads as 5.
const LEVEL_NAMES: Record<number, string> = { 4: 'operator', 5: 'full trust' };

export const at001 = defineCheck({
  id: 'AT-001',
  name: 'Atomic Agent Approval Ladder Raised',
  category: 'atomic-agent',
  severity: 'critical',
  description: 'agent.approvalLevel set to 4 (operator — shell commands and skill scripts run without approval) or 5 (full trust — every tool call, including MCP tools and writes to config.json/.env, runs unprompted), or legacy agent.approvalRequired: false (loads as level 5).',
  supportedAgents: ['atomic-agent'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    let worst = 0;
    for (const config of atomicConfigs(ctx.configs)) {
      const level = getNestedValue(config.data, 'agent.approvalLevel');
      const legacyOff = getNestedValue(config.data, 'agent.approvalRequired') === false;
      const effective = typeof level === 'number' ? level : legacyOff ? 5 : undefined;
      if (effective === undefined || effective < 4) continue;
      worst = Math.max(worst, effective);
      evidence.push({
        file: config.filePath,
        snippet: typeof level === 'number' ? `agent.approvalLevel: ${level}` : 'agent.approvalRequired: false',
        detail: effective >= 5
          ? `Approval level ${effective} (${LEVEL_NAMES[5]}) — every tool call runs without confirmation, including MCP tools, reads outside the working directory and edits to the agent's own config and secrets`
          : `Approval level ${effective} (${LEVEL_NAMES[4]}) — shell commands, skill scripts and process termination run without confirmation`,
      });
    }
    return h.fromEvidence(evidence, {
      passed: 'Atomic Agent approval level keeps shell and tool calls gated',
      failed: () => 'Atomic Agent approval ladder is raised — dangerous tool calls run without confirmation',
      severity: worst === 4 ? 'warning' : undefined,
      fixDescription: 'Lower agent.approvalLevel to 1–3 (`atomic-agent config set agent.approvalLevel 2`); use `--no-approval` for a single trusted run instead of a persistent setting',
    });
  },
});
