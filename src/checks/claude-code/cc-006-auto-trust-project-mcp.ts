import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

export const cc006 = defineCheck({
  id: 'CC-006',
  name: 'Auto-Trust Project MCP Servers',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Detect enableAllProjectMcpServers, which trusts MCP servers from any project .mcp.json',
  supportedAgents: ['claude-code'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      if (config.data.enableAllProjectMcpServers === true) {
        evidence.push({
          file: config.filePath,
          detail: 'enableAllProjectMcpServers = true — every project-level .mcp.json is auto-trusted',
        });
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'Project-level MCP servers require explicit trust',
      failed: () => 'enableAllProjectMcpServers is on — any cloned repo can run MCP servers without prompting',
      fixDescription: 'Remove enableAllProjectMcpServers, or use enabledMcpjsonServers for an explicit allowlist',
    });
  },
});
