import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { maskArgSecrets, maskUrlSecrets } from '../../mcp/config-secrets.js';

export const mcp001 = defineCheck({
  id: 'MCP-001',
  name: 'MCP Config Discovery',
  category: 'mcp',
  severity: 'info',
  description: 'Inventory all configured MCP servers across all agent configs',
  supportedAgents: ['mcp'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    const mcpConfigs = ctx.mcpConfigs ?? [];

    for (const config of mcpConfigs) {
      for (const server of config.servers) {
        // The inventory quotes the URL and argv: a credential written there
        // (`/api/mcp/s/<secret>/`, `--token x`) is masked as MCP-003 finds it
        const detail = [
          `Transport: ${server.transport}`,
          server.command ? `Command: ${server.command}` : null,
          server.url ? `URL: ${maskUrlSecrets(server.url)}` : null,
          server.args?.length ? `Args: ${maskArgSecrets(server.args).join(' ')}` : null,
          server.env ? `Env vars: ${Object.keys(server.env).join(', ')}` : null,
        ].filter(Boolean).join(', ');

        evidence.push({
          file: config.filePath,
          snippet: `Server: ${server.name}`,
          detail,
        });
      }
    }

    const totalServers = mcpConfigs.reduce((sum, c) => sum + c.servers.length, 0);
    const found = totalServers === 0
      ? 'No MCP servers configured'
      : `Found ${totalServers} MCP server(s) across ${mcpConfigs.length} config(s)`;

    // Compiled servers (Go/Rust binaries): no source to analyze, so the
    // source checks pass them unseen. An info note — not an incomplete scan.
    const compiled = (ctx.mcpServerSources ?? []).filter((s) => s.compiledBinary);
    for (const s of compiled) {
      const kind = /executable|WebAssembly/.test(s.compiledBinary!) ? `compiled binary (${s.compiledBinary})` : s.compiledBinary!;
      evidence.push({
        file: s.localPath ?? s.serverName,
        snippet: `Server: ${s.serverName} (compiled binary, source not analysed)`,
        detail: `${kind} — source not analysed`,
      });
    }
    if (compiled.length > 0) {
      return h.result({
        passed: false,
        message: `${found}; ${compiled.length} run a compiled binary — source not analysed`,
        evidence,
      });
    }

    return h.result({
      passed: true,
      message: found,
      evidence,
    });
  },
});
