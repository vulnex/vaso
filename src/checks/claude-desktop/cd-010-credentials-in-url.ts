import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { findArgSecrets, findUrlSecrets, findValueSecrets, headerSecret } from '../../mcp/config-secrets.js';

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
        // The same passed as arguments: `npx mcp-remote https://…/<secret>`,
        // `mcp-remote <url> --header "Authorization: Bearer <tok>"` (the
        // documented Claude Desktop remote-auth form), `-H "X-API-Key: <k>"`,
        // a database URL or connection string with its password
        const args = Array.isArray(server.args) ? server.args.filter((a): a is string => typeof a === 'string') : [];
        for (const secret of findArgSecrets(args)) {
          if (secret.via !== 'url' && secret.via !== 'header' && secret.via !== 'connection') continue;
          evidence.push({
            file: config.filePath,
            snippet: `mcpServers.${name}.${secret.location} = ${secret.masked}`,
            // (a header's kind already names its argument)
            detail: `${capitalize(secret.kind)}${secret.via === 'header' ? '' : secret.via === 'url' ? ' in a URL argument' : ' in an argument'} — readable in this config and by any local user via the process list`,
          });
        }
        // `DATABASE_URL=postgres://u:<pw>@db`, `REDIS_URL`, a connection string in env
        const env = server.env as Record<string, unknown> | undefined;
        if (env && typeof env === 'object') {
          for (const [ek, ev] of Object.entries(env)) {
            if (typeof ev !== 'string') continue;
            for (const secret of findValueSecrets(ev, `env.${ek}`)) {
              evidence.push({
                file: config.filePath,
                snippet: `mcpServers.${name}.env.${ek} = ${secret.masked}`,
                detail: `${capitalize(secret.kind)} — stored in plaintext in this config and handed to the server process`,
              });
            }
          }
        }

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
