import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

const HTTP_URL = /^http:\/\//i;
const LOOPBACK_HOST = /^http:\/\/(?:localhost|127\.0\.0\.1)(?:[:/]|$)/i;

export const dev005 = defineCheck({
  id: 'DEV-005',
  name: 'Devin Insecure MCP URL',
  category: 'coding-agent',
  severity: 'critical',
  description: 'Detect Devin MCP servers configured with plaintext http:// URLs (non-loopback), including sse transports',
  supportedAgents: ['devin'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      const servers = config.data.mcpServers as Record<string, unknown> | undefined;
      if (!servers || typeof servers !== 'object') continue;

      for (const [name, serverRaw] of Object.entries(servers)) {
        if (!serverRaw || typeof serverRaw !== 'object') continue;
        const server = serverRaw as Record<string, unknown>;
        const url = server.url;
        if (typeof url !== 'string') continue;
        if (!HTTP_URL.test(url)) continue;
        if (LOOPBACK_HOST.test(url)) continue;

        const transport = typeof server.transport === 'string' ? server.transport : undefined;
        evidence.push({
          file: config.filePath,
          snippet: `mcpServers.${name}.url: ${url}`,
          detail: `Plaintext http:// MCP URL${transport === 'sse' ? ' (sse transport)' : ''} — tool traffic, headers, and OAuth tokens travel unencrypted`,
        });
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'No Devin MCP servers use plaintext http:// URLs',
      failed: (n) => `Found ${n} Devin MCP server(s) with plaintext http:// URLs`,
      fixDescription: 'Switch the MCP server URL to https:// (loopback http is exempt)',
    });
  },
});
