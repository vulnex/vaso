import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

// Devin supports secret interpolation: ${env:VAR} and ${file:/path}. Any
// other value is a literal stored in plaintext on disk.
const INTERPOLATED = /^\$\{(?:env|file):[^}]*\}$/;

const SECRET_KEY_HINT = /(KEY|TOKEN|SECRET|PASS|API|AUTH)/i;
const MIN_SECRET_LENGTH = 8;

function mask(value: string): string {
  return `${value.slice(0, 4)}…(${value.length} chars)`;
}

function isLiteralSecret(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && !INTERPOLATED.test(value);
}

export const dev003 = defineCheck({
  id: 'DEV-003',
  name: 'Devin Plaintext Secrets in MCP Config',
  category: 'coding-agent',
  severity: 'critical',
  description: 'Detect literal secrets in Devin mcpServers env/headers/oauthClientSecret instead of ${env:VAR}/${file:/path} interpolation — including Devin API tokens (cog_ current; apk_/apk_user_ legacy)',
  supportedAgents: ['devin'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      const servers = config.data.mcpServers as Record<string, unknown> | undefined;
      if (!servers || typeof servers !== 'object') continue;

      for (const [name, serverRaw] of Object.entries(servers)) {
        if (!serverRaw || typeof serverRaw !== 'object') continue;
        const server = serverRaw as Record<string, unknown>;

        // A literal oauthClientSecret is always a finding — the field is a
        // secret by definition.
        if (isLiteralSecret(server.oauthClientSecret)) {
          evidence.push({
            file: config.filePath,
            snippet: `mcpServers.${name}.oauthClientSecret: ${mask(server.oauthClientSecret)}`,
            detail: 'Literal OAuth client secret in MCP config — use ${env:VAR} or ${file:/path} interpolation',
          });
        }

        // env/headers: flag secret-suggesting key names with literal values
        for (const field of ['env', 'headers'] as const) {
          const map = server[field];
          if (!map || typeof map !== 'object' || Array.isArray(map)) continue;
          for (const [key, value] of Object.entries(map as Record<string, unknown>)) {
            if (!SECRET_KEY_HINT.test(key)) continue;
            if (!isLiteralSecret(value) || value.length < MIN_SECRET_LENGTH) continue;
            evidence.push({
              file: config.filePath,
              snippet: `mcpServers.${name}.${field}.${key}: ${mask(value)}`,
              detail: `Literal secret-like value for "${key}" in MCP ${field} — use \${env:VAR} or \${file:/path} interpolation`,
            });
          }
        }
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'No plaintext secrets detected in Devin MCP configs',
      failed: (n) => `Found ${n} plaintext secret(s) in Devin MCP configs`,
      fixDescription: 'Move secrets into environment variables or files and reference them via ${env:VAR} / ${file:/path}; rotate any exposed credential',
    });
  },
});
