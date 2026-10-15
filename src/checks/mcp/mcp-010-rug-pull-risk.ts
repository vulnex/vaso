import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { runnerPackage, isPinnedOrLocal, pinProblem } from '../../mcp/package-pin.js';

export const mcp010 = defineCheck({
  id: 'MCP-010',
  name: 'Rug Pull Risk',
  category: 'mcp',
  severity: 'warning',
  description: 'Detect unpinned versions and missing lockfiles that enable supply chain attacks',
  supportedAgents: ['mcp'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    const mcpConfigs = ctx.mcpConfigs ?? [];

    for (const config of mcpConfigs) {
      for (const server of config.servers) {
        if (!server.command || !server.args?.length) continue;

        const pkg = runnerPackage(server.command, server.args);
        if (!pkg || isPinnedOrLocal(pkg)) continue;
        evidence.push({
          file: config.filePath,
          snippet: `Server "${server.name}": ${pkg.runner} ${pkg.spec}`,
          detail: pkg.ecosystem === 'npm'
            ? `Package ${pinProblem(pkg)} — every launch fetches what the registry serves, enabling rug-pull attacks`
            : `Python package ${pinProblem(pkg)} — enables rug-pull attacks`,
        });
        // Auto-install without a prompt makes an unpinned package worse
        if (pkg.ecosystem === 'npm' && server.args.some(a => a === '-y' || a === '--yes')) {
          evidence.push({
            file: config.filePath,
            snippet: `Server "${server.name}": ${pkg.runner} -y (auto-install)`,
            detail: 'Auto-install enabled with unpinned package — will install without confirmation',
          });
        }
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'MCP server packages are properly version-pinned',
      failed: (n) => `Found ${n} supply chain risk(s) from unpinned versions`,
      fixDescription: 'Pin package versions (e.g., npx @scope/package@1.2.3)',
    });
  },
});
