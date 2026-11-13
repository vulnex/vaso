import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { runnerPackage, isPinnedOrLocal, pinProblem } from '../../mcp/package-pin.js';
import { isDisabledServerConfig } from '../../mcp/disabled.js';


export const cdx004 = defineCheck({
  id: 'CDX-004',
  name: 'Codex Unpinned MCP Server',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Detect MCP servers in Codex config launched via package runners without a pinned version',
  supportedAgents: ['codex'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      const servers = config.data.mcp_servers as Record<string, unknown> | undefined;
      if (!servers || typeof servers !== 'object') continue;

      for (const [name, server] of Object.entries(servers)) {
        if (isDisabledServerConfig(server)) continue; // never launched
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
          snippet: `mcp_servers.${name}: ${command} ${argList.join(' ')}`,
          detail: `${pinProblem(pkg)} — supply chain risk`,
        });
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'All Codex MCP server packages are version-pinned',
      failed: (n) => `Found ${n} Codex MCP server(s) running unpinned packages`,
      fixDescription: 'Pin packages to a specific version in [mcp_servers.*] config',
    });
  },
});
