import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { markUntrustedWorkspace } from '../../adapters/folder-trust.js';
import { qwenWorkspaceTrusted } from '../../adapters/qwen-code.js';
import { runnerPackage, isPinnedOrLocal, pinProblem } from '../../mcp/package-pin.js';
import { isDisabledServerConfig } from '../../mcp/disabled.js';


export const qc006 = defineCheck({
  id: 'QC-006',
  name: 'Qwen Unpinned MCP Server',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Detect MCP servers in Qwen config launched via package runners without a pinned version',
  supportedAgents: ['qwen-code'],

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

    await markUntrustedWorkspace(ctx, evidence, qwenWorkspaceTrusted);

    return h.fromEvidence(evidence, {
      passed: 'All Qwen MCP server packages are version-pinned',
      failed: (n) => `Found ${n} Qwen MCP server(s) running unpinned packages`,
      fixDescription: 'Pin packages in mcpServers.<name>.args (e.g. "@modelcontextprotocol/server-foo@1.2.3")',
    });
  },
});
