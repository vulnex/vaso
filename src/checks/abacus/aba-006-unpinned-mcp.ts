import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { markUntrustedProject, mcpServers } from './shared.js';

const PACKAGE_RUNNERS = new Set(['npx', 'uvx', 'bunx', 'pnpx']);
const PINNED = /@\d+\.\d+\.\d+|==\d+\.\d+/;
const SHA_PINNED = /(?:@sha256:|#[a-f0-9]{7,40})/i;

export const aba006 = defineCheck({
  id: 'ABA-006',
  name: 'Abacus.AI Unpinned MCP Package',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Detect Abacus.AI stdio MCP servers launched through npx/uvx/bunx without a pinned package version',
  supportedAgents: ['abacus'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    for (const { config, server, path } of mcpServers(ctx.configs)) {
      if (typeof server.command !== 'string') continue;
      const runner = server.command.split(/[\\/]/).pop() ?? server.command;
      if (!PACKAGE_RUNNERS.has(runner)) continue;
      const args = Array.isArray(server.args) ? server.args.filter((a): a is string => typeof a === 'string') : [];
      const pkg = args.find(a => !a.startsWith('-'));
      if (!pkg || PINNED.test(pkg) || SHA_PINNED.test(pkg)) continue;
      evidence.push({
        file: config.filePath,
        snippet: `${path}: ${server.command} ${args.join(' ')}`,
        detail: `Runs "${pkg}" via ${runner} with no version pin — every launch fetches whatever is published`,
      });
    }

    await markUntrustedProject(ctx, evidence);
    return h.fromEvidence(evidence, {
      passed: 'All Abacus.AI MCP server packages are version-pinned',
      failed: (n) => `Found ${n} Abacus.AI MCP server(s) running unpinned packages`,
      fixDescription: 'Pin MCP packages to an exact version (e.g. @scope/server@1.2.3)',
    });
  },
});
