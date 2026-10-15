import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { API_KEY_PATTERNS, isPlaceholderSecret } from '../../core/patterns.js';

// Devin supports secret interpolation: ${env:VAR} and ${file:/path}, also
// embedded in a larger value (`Bearer ${env:TOKEN}`). Whatever remains after
// removing interpolations and an auth scheme is a literal stored on disk.
const INTERPOLATION = /\$\{(?:env|file):[^}]*\}/g;
const AUTH_SCHEME = /^\s*(?:Bearer|Basic|Token)\b\s*/i;

const SECRET_KEY_HINT = /(KEY|TOKEN|SECRET|PASS|API|AUTH)/i;
const MIN_SECRET_LENGTH = 8;

function mask(value: string): string {
  return `${value.slice(0, 4)}…(${value.length} chars)`;
}

/** The literal (non-interpolated) part of a value, or '' when fully interpolated. */
function literalPart(value: unknown): string {
  if (typeof value !== 'string') return '';
  return value.replace(INTERPOLATION, '').replace(AUTH_SCHEME, '').trim();
}

function isLiteralSecret(value: unknown): value is string {
  const literal = literalPart(value);
  return literal.length > 0 && !isPlaceholderSecret(literal);
}

function knownTokenName(value: string): string | undefined {
  return API_KEY_PATTERNS.find(p => p.pattern.test(value))?.name;
}

export const dev003 = defineCheck({
  id: 'DEV-003',
  name: 'Devin Plaintext Secrets in MCP Config',
  category: 'coding-agent',
  severity: 'critical',
  description: 'Detect literal secrets in Devin mcpServers env/headers/oauthClientSecret instead of ${env:VAR}/${file:/path} interpolation — including Devin API tokens (devin- current; cog_/apk_/apk_user_ legacy)',
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
            if (typeof value !== 'string') continue;
            const literal = literalPart(value);
            if (isPlaceholderSecret(literal)) continue; // a docs example (ghp_your_token)
            // A recognizable token format is a finding under any key name
            const tokenName = knownTokenName(literal);
            if (!tokenName && !SECRET_KEY_HINT.test(key)) continue;
            if (literal.length < MIN_SECRET_LENGTH) continue;
            evidence.push({
              file: config.filePath,
              snippet: `mcpServers.${name}.${field}.${key}: ${mask(value)}`,
              detail: tokenName
                ? `Plaintext ${tokenName} in MCP ${field} "${key}" — use \${env:VAR} or \${file:/path} interpolation`
                : `Literal secret-like value for "${key}" in MCP ${field} — use \${env:VAR} or \${file:/path} interpolation`,
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
