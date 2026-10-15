import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { isPlaintextRemoteUrl } from '../windsurf-app/plaintext-url.js';

const URL_FIELDS = ['url', 'httpUrl', 'sseUrl'];

export const ghc004 = defineCheck({
  id: 'GHC-004',
  name: 'Copilot CLI MCP Server Over Plaintext HTTP',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Detect MCP servers in workspace .mcp.json/.github/mcp.json or user mcp-config.json that use http:// rather than https://',
  supportedAgents: ['copilot-cli'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    type Source = { path: string; data: Record<string, unknown> };
    const sources: Source[] = [];

    // Use already-parsed .mcp.json from ctx.configs (the adapter appends
    // project-level .mcp.json to the config list).
    for (const c of ctx.configs) {
      // project .mcp.json / .github/mcp.json, user <config dir>/mcp-config.json
      if (c.filePath.endsWith('.mcp.json') || c.filePath.endsWith('/.github/mcp.json') || c.filePath.endsWith('/mcp-config.json')) {
        sources.push({ path: c.filePath, data: c.data });
      }
    }


    for (const { path, data } of sources) {
      const servers = data.mcpServers as Record<string, unknown> | undefined;
      if (!servers || typeof servers !== 'object') continue;

      for (const [name, server] of Object.entries(servers)) {
        if (!server || typeof server !== 'object') continue;
        const obj = server as Record<string, unknown>;
        for (const field of URL_FIELDS) {
          const value = obj[field];
          if (typeof value !== 'string') continue;
          // localhost MCP is a common dev pattern with no exposure
          if (!isPlaintextRemoteUrl(value)) continue;
          evidence.push({
            file: path,
            snippet: `mcpServers.${name}.${field} = ${value}`,
            detail: 'MCP traffic over plaintext HTTP — bearer tokens in headers traverse unencrypted',
          });
        }
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'No Copilot CLI MCP servers using plaintext HTTP',
      failed: (n) => `Found ${n} Copilot CLI MCP server(s) using plaintext HTTP`,
      fixDescription: 'Switch the MCP server URL to https:// (or proxy via TLS)',
    });
  },
});
