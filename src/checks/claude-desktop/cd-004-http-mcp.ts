import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

export const cd004 = defineCheck({
  id: 'CD-004',
  name: 'Cleartext HTTP MCP Server',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Detect MCP servers configured with http:// URLs (no TLS)',
  supportedAgents: ['claude-desktop'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      const mcpServers = config.data.mcpServers as Record<string, unknown> | undefined;
      if (!mcpServers || typeof mcpServers !== 'object') continue;
      for (const [name, srv] of Object.entries(mcpServers)) {
        if (!srv || typeof srv !== 'object') continue;
        const url = (srv as Record<string, unknown>).url;
        if (typeof url !== 'string') continue;
        if (!/^http:\/\//i.test(url)) continue;
        // Tolerate loopback — local-only servers can't be MITM'd off-host.
        if (/^http:\/\/(localhost|127\.0\.0\.1|\[::1\])(?::\d+)?(?:\/|$)/i.test(url)) continue;

        evidence.push({
          file: config.filePath,
          snippet: `mcpServers.${name}.url = ${url}`,
          detail: 'MCP server reached over plaintext HTTP — tokens, prompts, and tool calls travel unencrypted',
        });
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'No cleartext HTTP MCP servers configured',
      failed: (n) => `Found ${n} MCP server(s) using http:// (non-loopback)`,
      fixDescription: 'Switch the MCP server URL to https:// or proxy through a TLS-terminating gateway',
    });
  },
});
