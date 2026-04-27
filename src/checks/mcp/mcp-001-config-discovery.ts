import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

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
        const detail = [
          `Transport: ${server.transport}`,
          server.command ? `Command: ${server.command}` : null,
          server.url ? `URL: ${server.url}` : null,
          server.args?.length ? `Args: ${server.args.join(' ')}` : null,
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

    return h.result({
      passed: true,
      message: totalServers === 0
        ? 'No MCP servers configured'
        : `Found ${totalServers} MCP server(s) across ${mcpConfigs.length} config(s)`,
      evidence,
    });
  },
});
