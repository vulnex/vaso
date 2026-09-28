import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { atomicConfigs, isEnabled, mcpServers, serverName } from './shared.js';

export const at006 = defineCheck({
  id: 'AT-006',
  name: 'Atomic Agent MCP Server Trusted as Read-Only',
  category: 'atomic-agent',
  severity: 'warning',
  description: 'mcp.servers[].trust set to "pure_read" — every tool on that server skips the approval gate and is batched with local reads. The trust label is an operator assertion: Atomic Agent does not verify that the server\'s tools are actually read-only, and a server update can add write/exec tools that inherit it.',
  supportedAgents: ['atomic-agent'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    for (const config of atomicConfigs(ctx.configs)) {
      mcpServers(config.data).forEach((server, i) => {
        if (!isEnabled(server) || server.trust !== 'pure_read') return;
        const name = serverName(server, i);
        evidence.push({
          file: config.filePath,
          snippet: `mcp.servers[${name}].trust: "pure_read"`,
          detail: `All tools on MCP server "${name}" run without approval`,
        });
      });
    }
    return h.fromEvidence(evidence, {
      passed: 'Atomic Agent MCP servers are approval-gated',
      failed: (n) => `${n} Atomic Agent MCP server(s) bypass tool approval via trust "pure_read"`,
      fixDescription: 'Remove `trust: "pure_read"` (defaults to "approval_gated") unless every tool on the server is genuinely side-effect free and the server is version-pinned',
    });
  },
});
