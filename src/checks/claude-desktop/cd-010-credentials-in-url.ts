import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

const CRED_QUERY = /[?&](?:api[_-]?key|token|secret|password|access_token)=([^&]+)/i;
const BASIC_AUTH = /^https?:\/\/[^/@]+:[^/@]+@/i;
const BEARER_HEADER_VALUE = /^Bearer\s+[A-Za-z0-9._\-~+/=]{12,}$/i;

export const cd010 = defineCheck({
  id: 'CD-010',
  name: 'Credentials Embedded in MCP URL/Headers',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Detect MCP server URLs with embedded basic-auth or query-string credentials, or static Bearer tokens in headers',
  supportedAgents: ['claude-desktop'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      const mcpServers = config.data.mcpServers as Record<string, unknown> | undefined;
      if (!mcpServers || typeof mcpServers !== 'object') continue;

      for (const [name, srv] of Object.entries(mcpServers)) {
        if (!srv || typeof srv !== 'object') continue;
        const server = srv as Record<string, unknown>;

        const url = typeof server.url === 'string' ? server.url : undefined;
        if (url) {
          if (BASIC_AUTH.test(url)) {
            evidence.push({
              file: config.filePath,
              snippet: `mcpServers.${name}.url contains user:pass@host`,
              detail: 'HTTP basic-auth credentials embedded in URL — visible to anyone who can read this config',
            });
          } else if (CRED_QUERY.test(url)) {
            evidence.push({
              file: config.filePath,
              snippet: `mcpServers.${name}.url contains credential query parameter`,
              detail: 'API token in query string — gets logged by upstream proxies and may leak via Referer',
            });
          }
        }

        const headers = server.headers as Record<string, unknown> | undefined;
        if (headers && typeof headers === 'object') {
          for (const [hk, hv] of Object.entries(headers)) {
            if (typeof hv !== 'string') continue;
            if (BEARER_HEADER_VALUE.test(hv)) {
              evidence.push({
                file: config.filePath,
                snippet: `mcpServers.${name}.headers.${hk} = "Bearer …"`,
                detail: 'Static Bearer token stored in plaintext header — rotate and source from a secret manager instead',
              });
            }
          }
        }
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'No credentials embedded in MCP URLs or headers',
      failed: (n) => `Found ${n} embedded credential(s) in MCP URL/headers`,
      fixDescription: 'Move credentials out of mcpServers.*.url / .headers; use a secret manager or env-var indirection',
    });
  },
});
