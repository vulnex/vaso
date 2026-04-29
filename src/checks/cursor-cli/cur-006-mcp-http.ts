import { join } from 'node:path';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { stripJsonc } from '../../core/jsonc.js';

const URL_FIELDS = ['url', 'httpUrl', 'sseUrl'];

export const cur006 = defineCheck({
  id: 'CUR-006',
  name: 'Cursor MCP Server Over Plaintext HTTP',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Detect MCP servers in ~/.cursor/mcp.json configured to use http:// rather than https://',
  supportedAgents: ['cursor-cli'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    const mcpPath = join(ctx.installation.installDir, 'mcp.json');
    if (!(await ctx.fs.access(mcpPath))) {
      return h.passed('No mcp.json present');
    }

    let parsed: Record<string, unknown>;
    try {
      const raw = await ctx.fs.readFile(mcpPath);
      parsed = JSON.parse(stripJsonc(raw)) as Record<string, unknown>;
    } catch {
      return h.passed('mcp.json could not be parsed');
    }

    const servers = parsed.mcpServers as Record<string, unknown> | undefined;
    if (!servers || typeof servers !== 'object') {
      return h.passed('No MCP servers configured');
    }

    for (const [name, server] of Object.entries(servers)) {
      if (!server || typeof server !== 'object') continue;
      const obj = server as Record<string, unknown>;
      for (const field of URL_FIELDS) {
        const value = obj[field];
        if (typeof value !== 'string') continue;
        if (!value.startsWith('http://')) continue;
        if (/^http:\/\/(localhost|127\.0\.0\.1|\[::1\])/i.test(value)) continue;
        evidence.push({
          file: mcpPath,
          snippet: `mcpServers.${name}.${field} = ${value}`,
          detail: 'MCP traffic over plaintext HTTP — bearer tokens in headers traverse unencrypted',
        });
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'All Cursor MCP servers use HTTPS or localhost transports',
      failed: (n) => `Found ${n} Cursor MCP server(s) using plaintext HTTP`,
      fixDescription: 'Switch the server URL to https:// (or move it behind a TLS-terminating proxy)',
    });
  },
});
