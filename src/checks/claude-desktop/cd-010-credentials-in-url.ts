import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { findUrlSecrets, headerSecret } from '../../mcp/config-secrets.js';

export const cd010 = defineCheck({
  id: 'CD-010',
  name: 'Credentials Embedded in MCP URL/Headers',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Detect MCP server URLs with embedded credentials (basic-auth, query/fragment parameters, secret paths), or static tokens in headers',
  supportedAgents: ['claude-desktop'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      const mcpServers = config.data.mcpServers as Record<string, unknown> | undefined;
      if (!mcpServers || typeof mcpServers !== 'object') continue;

      for (const [name, srv] of Object.entries(mcpServers)) {
        if (!srv || typeof srv !== 'object') continue;
        const server = srv as Record<string, unknown>;

        // userinfo, credential query/fragment parameters, and paths that are
        // the credential (Zapier MCP, Slack/Discord webhooks, random tokens)
        const url = typeof server.url === 'string' ? server.url : undefined;
        if (url) {
          for (const secret of findUrlSecrets(url)) {
            evidence.push({
              file: config.filePath,
              snippet: `mcpServers.${name}.url = ${secret.masked}`,
              detail: `${capitalize(secret.kind)} — the URL is stored, logged and synced as written; anyone who reads this config can use it`,
            });
          }
        }
        // `npx mcp-remote https://…/<secret>`: the same URL passed as an argument
        const args = Array.isArray(server.args) ? server.args : [];
        args.forEach((arg, i) => {
          if (typeof arg !== 'string' || !/^[a-z][a-z0-9+.-]*:\/\//i.test(arg)) return;
          for (const secret of findUrlSecrets(arg, `args[${i}]`)) {
            evidence.push({
              file: config.filePath,
              snippet: `mcpServers.${name}.args[${i}] = ${secret.masked}`,
              detail: `${capitalize(secret.kind)} in a URL argument — readable in this config and by any local user via the process list`,
            });
          }
        });

        const headers = server.headers as Record<string, unknown> | undefined;
        if (headers && typeof headers === 'object') {
          for (const [hk, hv] of Object.entries(headers)) {
            if (typeof hv !== 'string') continue;
            const kind = headerSecret(hk, hv);
            if (kind) {
              evidence.push({
                file: config.filePath,
                snippet: `mcpServers.${name}.headers.${hk} = ${/^\s*bearer\s/i.test(hv) ? '"Bearer …"' : '"…"'}`,
                detail: `Static ${kind}, stored in plaintext — rotate it and source it from a secret manager instead`,
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

function capitalize(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1);
}
