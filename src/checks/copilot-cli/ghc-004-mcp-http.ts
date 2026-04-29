import { join } from 'node:path';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { stripJsonc } from '../../core/jsonc.js';

const URL_FIELDS = ['url', 'httpUrl', 'sseUrl'];

export const ghc004 = defineCheck({
  id: 'GHC-004',
  name: 'Copilot CLI MCP Server Over Plaintext HTTP',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Detect MCP servers in workspace .mcp.json that use http:// rather than https://',
  supportedAgents: ['copilot-cli'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    type Source = { path: string; data: Record<string, unknown> };
    const sources: Source[] = [];

    // Use already-parsed .mcp.json from ctx.configs (the adapter appends
    // project-level .mcp.json to the config list).
    for (const c of ctx.configs) {
      if (c.filePath.endsWith('.mcp.json')) {
        sources.push({ path: c.filePath, data: c.data });
      }
    }

    // Also probe cwd directly for the case where the project install wasn't
    // detected as a separate installation (e.g. when a user runs `vaso scan`
    // from inside a repo that just has a .mcp.json but no ~/.copilot/ state).
    const cwdMcp = join(process.cwd(), '.mcp.json');
    const alreadyHandled = sources.some(s => s.path === cwdMcp);
    if (!alreadyHandled && (await ctx.fs.access(cwdMcp))) {
      try {
        const raw = await ctx.fs.readFile(cwdMcp);
        const data = JSON.parse(stripJsonc(raw)) as Record<string, unknown>;
        sources.push({ path: cwdMcp, data });
      } catch {}
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
          if (!value.startsWith('http://')) continue;
          if (/^http:\/\/(localhost|127\.0\.0\.1|\[::1\])/i.test(value)) continue;
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
