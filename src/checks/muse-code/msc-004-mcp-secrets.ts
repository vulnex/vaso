import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { secretShape } from '../../core/patterns.js';
import { isSecretNamedValue } from '../../analyzers/secret-values.js';
import { findArgSecrets, findUrlSecrets, headerSecret } from '../../mcp/config-secrets.js';
import { mcpServers } from './shared.js';

const cap = (s: string) => s.charAt(0).toUpperCase() + s.slice(1);

export const msc004 = defineCheck({
  id: 'MSC-004',
  name: 'Muse Code Plaintext Secrets in MCP Config',
  category: 'coding-agent',
  severity: 'critical',
  description: 'Detect literal secrets in Meta Muse Code MCP servers (settings.json mcpServers, project .mcp.json): env values, static headers (muse mcp add -H), arguments and URLs — Muse supports bearer_token_env_var and ${VAR} references instead',
  supportedAgents: ['muse-code'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    for (const { config, server, path } of mcpServers(ctx.configs)) {
      const env = server.env;
      if (env && typeof env === 'object' && !Array.isArray(env)) {
        for (const [key, value] of Object.entries(env as Record<string, unknown>)) {
          if (typeof value !== 'string' || !isSecretNamedValue(key, value)) continue;
          evidence.push({ file: config.filePath, snippet: `${path}.env.${key}: ${secretShape(value)}`, detail: `Literal secret for "${key}" in MCP env` });
        }
      }
      const headers = server.headers;
      if (headers && typeof headers === 'object' && !Array.isArray(headers)) {
        for (const [key, value] of Object.entries(headers as Record<string, unknown>)) {
          if (typeof value !== 'string') continue;
          const kind = headerSecret(key, value);
          if (!kind) continue;
          evidence.push({ file: config.filePath, snippet: `${path}.headers.${key}: ${secretShape(value)}`, detail: `${cap(kind)} stored in the MCP config` });
        }
      }
      const args = Array.isArray(server.args) ? server.args.filter((a): a is string => typeof a === 'string') : [];
      for (const secret of findArgSecrets(args, typeof server.command === 'string' ? server.command : undefined)) {
        evidence.push({
          file: config.filePath,
          snippet: `${path}.${secret.location}: ${secret.masked}`,
          detail: `${cap(secret.kind)} in an MCP server argument — stored in this config and visible to any local user in the process list`,
        });
      }
      if (typeof server.url === 'string') {
        for (const secret of findUrlSecrets(server.url, 'url')) {
          evidence.push({
            file: config.filePath,
            snippet: `${path}.url: ${secret.masked}`,
            detail: `${cap(secret.kind)} in the MCP server URL — send it in a header from the environment instead`,
          });
        }
      }
    }
    return h.fromEvidence(evidence, {
      passed: 'No plaintext secrets in Muse Code MCP configs',
      failed: (n) => `Found ${n} plaintext secret(s) in Muse Code MCP configs`,
      fixDescription: 'Reference secrets from the environment (bearer_token_env_var, "${VAR}" values, `muse mcp add --env-var NAME`) or use `muse mcp login` for OAuth, then rotate the exposed credential',
    });
  },
});
