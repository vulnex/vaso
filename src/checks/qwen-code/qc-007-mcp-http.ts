import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

const URL_FIELDS = ['url', 'httpUrl', 'sseUrl'];

export const qc007 = defineCheck({
  id: 'QC-007',
  name: 'Qwen MCP Server Over Plaintext HTTP',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Detect Qwen MCP servers configured to use http:// rather than https://',
  supportedAgents: ['qwen-code'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      const servers = config.data.mcpServers as Record<string, unknown> | undefined;
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
            file: config.filePath,
            snippet: `mcpServers.${name}.${field} = ${value}`,
            detail: 'MCP traffic over plaintext HTTP — credentials, tool args, and prompts traverse unencrypted',
          });
        }
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'All Qwen MCP servers use HTTPS or localhost transports',
      failed: (n) => `Found ${n} Qwen MCP server(s) using plaintext HTTP`,
      fixDescription: 'Switch the server URL to https:// (or move it behind a TLS-terminating proxy)',
    });
  },
});
