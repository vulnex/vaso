import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { runnerPackage, isPinnedOrLocal, pinProblem } from '../../mcp/package-pin.js';
import { markUntrustedProject, mcpServers } from './shared.js';


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
      const pkg = runnerPackage(server.command, server.args);
      if (!pkg || isPinnedOrLocal(pkg)) continue;
      const args = Array.isArray(server.args) ? server.args.filter((a): a is string => typeof a === 'string') : [];
      evidence.push({
        file: config.filePath,
        snippet: `${path}: ${server.command} ${args.join(' ')}`,
        detail: `${pinProblem(pkg)} — every launch fetches whatever is published`,
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
