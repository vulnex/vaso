import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { literalSecret, mask, mcpServers } from './shared.js';

export const aba004 = defineCheck({
  id: 'ABA-004',
  name: 'Abacus.AI Plaintext Secrets in MCP Config',
  category: 'coding-agent',
  severity: 'critical',
  description: 'Detect literal secrets in Abacus.AI MCP server env, headers and OAuth client secrets (config.json, mcp.json, desktop mcp-<mode>.json) — the files are plain JSON and the desktop copies them into its runtime directory',
  supportedAgents: ['abacus'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    for (const { config, server, path } of mcpServers(ctx.configs)) {
      const oauth = server.oauth as Record<string, unknown> | undefined;
      // Placeholders (`<only if your provider issued one>`) and env references
      // are not secrets — judged like any other secret-named value
      if (oauth && typeof oauth.clientSecret === 'string' && literalSecret('clientSecret', oauth.clientSecret)) {
        evidence.push({
          file: config.filePath,
          snippet: `${path}.oauth.clientSecret: ${mask(oauth.clientSecret)}`,
          detail: 'Literal OAuth client secret in MCP config',
        });
      }

      for (const field of ['env', 'headers'] as const) {
        const map = server[field];
        if (!map || typeof map !== 'object' || Array.isArray(map)) continue;
        for (const [key, value] of Object.entries(map as Record<string, unknown>)) {
          if (typeof value !== 'string') continue;
          const kind = literalSecret(key, value);
          if (!kind) continue;
          const token = kind === 'secret' ? undefined : kind;
          evidence.push({
            file: config.filePath,
            snippet: `${path}.${field}.${key}: ${mask(value)}`,
            detail: token
              ? `Plaintext ${token} in MCP ${field} "${key}"`
              : `Literal secret-like value for "${key}" in MCP ${field}`,
          });
        }
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'No plaintext secrets in Abacus.AI MCP configs',
      failed: (n) => `Found ${n} plaintext secret(s) in Abacus.AI MCP configs`,
      fixDescription: 'Move secrets out of the MCP config (export them in the environment the CLI inherits, or use the server\'s own credential store) and rotate any exposed credential',
    });
  },
});
