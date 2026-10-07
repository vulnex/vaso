import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { markUntrustedProject, mcpServers } from './shared.js';

export const aba008 = defineCheck({
  id: 'ABA-008',
  name: 'Abacus.AI MCP Server Auto-Approve',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Detect Abacus.AI MCP servers whose tools are auto-approved wholesale (autoApprove: true or "*") — every tool the server exposes, including ones it adds later, runs without a prompt',
  supportedAgents: ['abacus'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    for (const { config, server, path } of mcpServers(ctx.configs)) {
      const auto = server.autoApprove;
      const wholesale = auto === true
        || auto === '*'
        || (Array.isArray(auto) && auto.some(t => t === '*' || t === '**'));
      if (!wholesale) continue;
      evidence.push({
        file: config.filePath,
        snippet: `${path}.autoApprove: ${JSON.stringify(auto)}`,
        detail: `Every tool on MCP server "${server.name ?? path.split('.').pop()}" runs without approval — a poisoned or compromised server acts unchecked`,
      });
    }

    await markUntrustedProject(ctx, evidence);
    return h.fromEvidence(evidence, {
      passed: 'No Abacus.AI MCP servers are auto-approved wholesale',
      failed: (n) => `Found ${n} Abacus.AI MCP server(s) with blanket auto-approval`,
      fixDescription: 'Replace autoApprove: true / "*" with an explicit list of read-only tools, or remove it',
    });
  },
});
