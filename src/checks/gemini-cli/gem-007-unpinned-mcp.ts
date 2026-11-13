import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { markUntrustedWorkspace } from '../../adapters/folder-trust.js';
import { geminiWorkspaceTrusted } from '../../adapters/gemini.js';
import { runnerPackage, isPinnedOrLocal, pinProblem } from '../../mcp/package-pin.js';
import { isDisabledServerConfig } from '../../mcp/disabled.js';


export const gem007 = defineCheck({
  id: 'GEM-007',
  name: 'Gemini Unpinned MCP Server',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Detect MCP servers in Gemini config launched via package runners without a pinned version',
  supportedAgents: ['gemini-cli'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      const servers = config.data.mcpServers as Record<string, unknown> | undefined;
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
          snippet: `mcpServers.${name}: ${command} ${argList.join(' ')}`,
          detail: `${pinProblem(pkg)} — supply chain risk`,
        });
      }
    }

    await markUntrustedWorkspace(ctx, evidence, geminiWorkspaceTrusted);

    return h.fromEvidence(evidence, {
      passed: 'All Gemini MCP server packages are version-pinned',
      failed: (n) => `Found ${n} Gemini MCP server(s) running unpinned packages`,
      fixDescription: 'Pin packages to a specific version in mcpServers.<name>.args (e.g. "@modelcontextprotocol/server-foo@1.2.3")',
    });
  },
});
