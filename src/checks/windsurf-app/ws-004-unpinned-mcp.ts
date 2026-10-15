import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { runnerPackage, isPinnedOrLocal, pinProblem } from '../../mcp/package-pin.js';

export const ws004 = defineCheck({
  id: 'WS-004',
  name: 'Windsurf Unpinned MCP Package',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Detect stdio MCP servers in mcp_config.json launched via npx/uvx/pnpm dlx without a pinned package version',
  supportedAgents: ['windsurf'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      const servers = config.data.mcpServers as Record<string, unknown> | undefined;
      if (!servers || typeof servers !== 'object') continue;

      for (const [name, server] of Object.entries(servers)) {
        if (!server || typeof server !== 'object') continue;
        const rec = server as Record<string, unknown>;
        const command = rec.command;
        if (typeof command !== 'string') continue;

        const pkg = runnerPackage(command, rec.args);
        if (!pkg || isPinnedOrLocal(pkg)) continue;
        const argList = Array.isArray(rec.args)
          ? (rec.args as unknown[]).filter((a): a is string => typeof a === 'string')
          : [];

        evidence.push({
          file: config.filePath,
          snippet: `mcpServers.${name}: ${command} ${argList.join(' ')}`,
          detail: `Runs ${pinProblem(pkg)} — supply chain risk (rug pull / compromised release auto-adopted)`,
        });
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'All Windsurf MCP server packages are version-pinned',
      failed: (n) => `Found ${n} Windsurf MCP server(s) running unpinned packages`,
      fixDescription: 'Pin packages to a specific version (e.g. @scope/server@1.2.3) in mcp_config.json',
    });
  },
});
