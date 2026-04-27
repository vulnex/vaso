import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

function isVersionPinned(packageArg: string): boolean {
  // Scoped packages: @scope/name@version
  if (packageArg.startsWith('@')) {
    const afterScope = packageArg.indexOf('/', 1);
    if (afterScope === -1) return false;
    const rest = packageArg.slice(afterScope + 1);
    // Must have @version after the package name, and not @latest
    const atIdx = rest.indexOf('@');
    if (atIdx === -1) return false;
    const version = rest.slice(atIdx + 1);
    return version !== 'latest' && version.length > 0;
  }

  // Unscoped packages: name@version
  const atIdx = packageArg.indexOf('@');
  if (atIdx === -1) return false;
  const version = packageArg.slice(atIdx + 1);
  return version !== 'latest' && version.length > 0;
}

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

        const cmd = server.command;
        const args = server.args;

        // npx without version pinning
        if (cmd === 'npx' || cmd === 'npx.cmd') {
          const packageArg = args.find(a => !a.startsWith('-'));
          const isUnpinned = packageArg && !isVersionPinned(packageArg);

          if (isUnpinned) {
            evidence.push({
              file: config.filePath,
              snippet: `Server "${server.name}": npx ${packageArg}`,
              detail: 'Package not version-pinned — npx will always fetch latest, enabling rug-pull attacks',
            });

            // Only flag auto-install when package is also unpinned
            if (args.some(a => a === '-y' || a === '--yes')) {
              evidence.push({
                file: config.filePath,
                snippet: `Server "${server.name}": npx -y (auto-install)`,
                detail: 'Auto-install enabled with unpinned package — will install without confirmation',
              });
            }
          }
        }

        // uvx without version pinning
        if (cmd === 'uvx' || cmd === 'uv') {
          const packageArg = args.find(a => !a.startsWith('-') && a !== 'run' && a !== 'tool');
          if (packageArg && !packageArg.includes('==') && !packageArg.includes('>=')) {
            evidence.push({
              file: config.filePath,
              snippet: `Server "${server.name}": ${cmd} ${packageArg}`,
              detail: 'Python package not version-pinned — enables rug-pull attacks',
            });
          }
        }
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'MCP server packages are properly version-pinned',
      failed: (n) => `Found ${n} supply chain risk(s) from unpinned versions`,
      fixable: evidence.length > 0,
      fixDescription: 'Pin package versions (e.g., npx @scope/package@1.2.3)',
    });
  },
});
