import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

const PACKAGE_RUNNERS = new Set(['npx', 'pnpm', 'yarn', 'bunx', 'uvx', 'pipx']);
const PINNED_PACKAGE = /@\d+\.\d+\.\d+/;
const SHA_PINNED = /(?:@sha256:|#[a-f0-9]{7,40})/i;

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
        if (!server || typeof server !== 'object') continue;
        const command = (server as Record<string, unknown>).command;
        const args = (server as Record<string, unknown>).args;
        if (typeof command !== 'string') continue;

        const baseCmd = command.split('/').pop() ?? command;
        if (!PACKAGE_RUNNERS.has(baseCmd)) continue;

        const argList = Array.isArray(args)
          ? (args as unknown[]).filter((a): a is string => typeof a === 'string')
          : [];
        const pkgArg = argList.find(a => !a.startsWith('-'));
        if (!pkgArg) continue;
        if (PINNED_PACKAGE.test(pkgArg) || SHA_PINNED.test(pkgArg)) continue;

        evidence.push({
          file: config.filePath,
          snippet: `mcpServers.${name}: ${command} ${argList.join(' ')}`,
          detail: `Runs "${pkgArg}" via ${baseCmd} with no version pin — supply chain risk`,
        });
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'All Qwen MCP server packages are version-pinned',
      failed: (n) => `Found ${n} Qwen MCP server(s) running unpinned packages`,
      fixDescription: 'Pin packages in mcpServers.<name>.args (e.g. "@modelcontextprotocol/server-foo@1.2.3")',
    });
  },
});
