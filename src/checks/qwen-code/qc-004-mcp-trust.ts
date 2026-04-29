import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

export const qc004 = defineCheck({
  id: 'QC-004',
  name: 'Qwen MCP Server Marked Trusted',
  category: 'coding-agent',
  severity: 'critical',
  description: 'Detect MCP servers with trust:true — bypasses tool-call approval',
  supportedAgents: ['qwen-code'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      const servers = config.data.mcpServers as Record<string, unknown> | undefined;
      if (!servers || typeof servers !== 'object') continue;
      for (const [name, server] of Object.entries(servers)) {
        if (!server || typeof server !== 'object') continue;
        if ((server as Record<string, unknown>).trust === true) {
          evidence.push({
            file: config.filePath,
            snippet: `mcpServers.${name}.trust = true`,
            detail: 'Tool calls from this MCP server execute without approval — equivalent to yolo for that server',
          });
        }
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'No Qwen MCP server is marked as trusted',
      failed: (n) => `Found ${n} Qwen MCP server(s) with trust:true`,
      fixDescription: 'Remove trust:true; rely on per-call approval or specific allow rules in permissions.allow',
    });
  },
});
