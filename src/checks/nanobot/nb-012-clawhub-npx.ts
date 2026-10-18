import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { asRecord, asStringArray, getPath, nanobotConfigs, pick } from './shared.js';
import { runnerPackage, isPinnedOrLocal, pinProblem } from '../../mcp/package-pin.js';

export const nb012 = defineCheck({
  id: 'NB-012',
  name: 'Unpinned MCP Server Package',
  category: 'nanobot',
  severity: 'warning',
  description: 'Detect stdio MCP servers in tools.mcpServers launched through a package runner (npx, bunx, pnpm/yarn dlx, npm exec, uvx, uv tool run, pipx run) without an exact version. The package is resolved from the registry on every start, so a compromised or typosquatted release runs with the agent\'s privileges and every env secret passed to it.',
  supportedAgents: ['nanobot'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    for (const config of nanobotConfigs(ctx.configs)) {
      const servers = asRecord(getPath(config.data, 'tools.mcpServers'));
      if (!servers) continue;
      for (const [name, raw] of Object.entries(servers)) {
        const server = asRecord(raw);
        if (!server) continue;
        const command = pick(server, 'command');
        if (typeof command !== 'string' || !command.trim()) continue;
        const args = asStringArray(pick(server, 'args'));
        const pkg = runnerPackage(command, args);
        if (!pkg || isPinnedOrLocal(pkg)) continue;
        evidence.push({
          file: config.filePath,
          snippet: `tools.mcpServers.${name}: ${[command, ...args].join(' ').slice(0, 120)}`,
          detail: `MCP server "${name}": ${pinProblem(pkg)} — fetched fresh from the registry on each start`,
        });
      }
    }
    return h.fromEvidence(evidence, {
      passed: 'No unpinned package-runner MCP servers in tools.mcpServers',
      failed: (n) => `${n} MCP server(s) run unpinned registry packages`,
      fixDescription: 'Pin an exact version in the args (e.g. "@modelcontextprotocol/server-filesystem@2025.8.21", "mcp-server-fetch==2025.4.7") or install the server locally and point command at it',
    });
  },
});
