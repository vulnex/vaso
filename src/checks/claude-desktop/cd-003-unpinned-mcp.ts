import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { runnerPackage, isPinnedOrLocal, pinProblem } from '../../mcp/package-pin.js';

interface ServerSpec {
  command?: string;
  args?: unknown;
}


function checkServer(name: string, server: ServerSpec, file: string, evidence: Evidence[]): void {
  const command = server.command;
  if (typeof command !== 'string') return;
  const pkg = runnerPackage(command, server.args);
  if (!pkg || isPinnedOrLocal(pkg)) return;
  const args = Array.isArray(server.args) ? (server.args as unknown[]).filter((a): a is string => typeof a === 'string') : [];

  evidence.push({
    file,
    snippet: `mcpServers.${name}: ${command} ${args.join(' ')}`,
    detail: `MCP server runs ${pinProblem(pkg)} — supply chain risk`,
  });
}

export const cd003 = defineCheck({
  id: 'CD-003',
  name: 'Unpinned MCP Server Package',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Detect MCP servers launched via npx/uvx/etc. without a pinned package version',
  supportedAgents: ['claude-desktop'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      const mcpServers = config.data.mcpServers as Record<string, unknown> | undefined;
      if (!mcpServers || typeof mcpServers !== 'object') continue;
      for (const [name, srv] of Object.entries(mcpServers)) {
        if (srv && typeof srv === 'object') {
          checkServer(name, srv as ServerSpec, config.filePath, evidence);
        }
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'All MCP server packages are version-pinned',
      failed: (n) => `Found ${n} MCP server(s) running unpinned packages`,
      fixDescription: 'Pin packages to a specific version (e.g. @modelcontextprotocol/server-foo@1.2.3)',
    });
  },
});
