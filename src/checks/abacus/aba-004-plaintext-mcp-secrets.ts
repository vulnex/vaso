import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { API_KEY_PATTERNS } from '../../core/patterns.js';
import { isEnvReference, mask, mcpServers } from './shared.js';

const SECRET_KEY_HINT = /(KEY|TOKEN|SECRET|PASS|API|AUTH|COOKIE|SESSION)/i;
const AUTH_SCHEME = /^\s*(?:Bearer|Basic|Token)\b\s*/i;
const MIN_SECRET_LENGTH = 8;

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
      if (oauth && typeof oauth.clientSecret === 'string' && oauth.clientSecret.length >= MIN_SECRET_LENGTH && !isEnvReference(oauth.clientSecret)) {
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
          if (typeof value !== 'string' || isEnvReference(value)) continue;
          const literal = value.replace(AUTH_SCHEME, '').trim();
          const token = API_KEY_PATTERNS.find(p => p.pattern.test(literal))?.name;
          if (!token && (!SECRET_KEY_HINT.test(key) || literal.length < MIN_SECRET_LENGTH)) continue;
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
