import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { runnerPackage, isPinnedOrLocal, pinProblem } from '../../mcp/package-pin.js';


export const dev004 = defineCheck({
  id: 'DEV-004',
  name: 'Devin Unpinned MCP Package',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Detect stdio MCP servers in Devin config launched via npx/uvx without a pinned version',
  supportedAgents: ['devin'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      const servers = config.data.mcpServers as Record<string, unknown> | undefined;
      if (!servers || typeof servers !== 'object') continue;

      for (const [name, server] of Object.entries(servers)) {
        if (!server || typeof server !== 'object') continue;
        const command = (server as Record<string, unknown>).command;
        const args = (server as Record<string, unknown>).args;
        if (typeof command !== 'string') continue;

        const pkg = runnerPackage(command, args);
        if (!pkg || isPinnedOrLocal(pkg)) continue;
        const argList = Array.isArray(args)
          ? (args as unknown[]).filter((a): a is string => typeof a === 'string')
          : [];

        evidence.push({
          file: config.filePath,
          snippet: `mcpServers.${name}: ${command} ${argList.join(' ')}`,
          detail: `${pinProblem(pkg)} — supply chain risk`,
        });
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'All Devin MCP server packages are version-pinned',
      failed: (n) => `Found ${n} Devin MCP server(s) running unpinned packages`,
      fixDescription: 'Pin packages to a specific version in mcpServers config (e.g. @scope/name@1.2.3)',
    });
  },
});
