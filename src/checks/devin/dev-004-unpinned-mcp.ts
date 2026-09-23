import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

const PACKAGE_RUNNERS = new Set(['npx', 'uvx']);
// Matches name@1.2.3 and @scope/name@1.2.3 (the pattern can appear anywhere
// in the argument, which covers scoped packages).
const PINNED_PACKAGE = /@\d+\.\d+\.\d+/;
const SHA_PINNED = /(?:@sha256:|#[a-f0-9]{7,40})/i;

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

        const baseCmd = command.split('/').pop() ?? command;
        if (!PACKAGE_RUNNERS.has(baseCmd)) continue;

        const argList = Array.isArray(args)
          ? (args as unknown[]).filter((a): a is string => typeof a === 'string')
          : [];
        // Skip runner flags (-y, --yes, …); the first non-flag arg is the package
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
      passed: 'All Devin MCP server packages are version-pinned',
      failed: (n) => `Found ${n} Devin MCP server(s) running unpinned packages`,
      fixDescription: 'Pin packages to a specific version in mcpServers config (e.g. @scope/name@1.2.3)',
    });
  },
});
