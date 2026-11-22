import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { API_KEY_PATTERNS, envReference, isPlaceholderSecret, secretShape, storedFallback } from '../../core/patterns.js';
import { findArgSecrets, findUrlSecrets } from '../../mcp/config-secrets.js';

// Devin supports secret interpolation: ${env:VAR} and ${file:/path}, also
// embedded in a larger value (`Bearer ${env:TOKEN}`). Whatever remains after
// removing interpolations and an auth scheme is a literal stored on disk.
const INTERPOLATION = /\$\{(?:env|file):[^}]*\}/g;
const AUTH_SCHEME = /^\s*(?:Bearer|Basic|Token)\b\s*/i;

const SECRET_KEY_HINT = /(KEY|TOKEN|SECRET|PASS|API|AUTH)/i;
const MIN_SECRET_LENGTH = 8;

const cap = (s: string) => s.charAt(0).toUpperCase() + s.slice(1);

function mask(value: string): string {
  return secretShape(value);
}

/** The literal (non-interpolated) part of a value, or '' when fully interpolated. */
function literalPart(value: unknown): string {
  if (typeof value !== 'string') return '';
  return value.replace(INTERPOLATION, '').replace(AUTH_SCHEME, '').trim();
}

function isLiteralSecret(value: unknown): value is string {
  const literal = literalPart(value);
  return literal.length > 0 && !isPlaceholderSecret(literal) && !envReference(literal);
}

/**
 * A reference in a syntax Devin doesn't expand (`${VAR}`, `$VAR`, `{env:VAR}`,
 * a bare variable name): Devin passes the text to the server as is. Nothing
 * is stored, so it isn't a plaintext secret — but the server gets no
 * credential. Reported as info.
 */
function unexpandedReference(value: unknown, where: string, file: string): Evidence | undefined {
  if (typeof value !== 'string') return undefined;
  const form = envReference(value);
  if (!form || form === 'env-colon') return undefined;
  return {
    file,
    snippet: `${where}: ${value.trim().slice(0, 60)}`,
    detail: 'Not Devin interpolation syntax — Devin expands only ${env:VAR} and ${file:/path}, so the MCP server receives this text literally (no credential is stored here)',
    mitigated: true,
  };
}

function knownTokenName(value: string): string | undefined {
  return API_KEY_PATTERNS.find(p => p.pattern.test(value))?.name;
}

export const dev003 = defineCheck({
  id: 'DEV-003',
  name: 'Devin Plaintext Secrets in MCP Config',
  category: 'coding-agent',
  severity: 'critical',
  description: 'Detect literal secrets in Devin mcpServers env/headers/oauthClientSecret/args/URL instead of ${env:VAR}/${file:/path} interpolation — including Devin API tokens (devin- current; cog_/apk_/apk_user_ legacy)',
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
        const oauthRef = unexpandedReference(server.oauthClientSecret, `mcpServers.${name}.oauthClientSecret`, config.filePath);
        if (oauthRef) evidence.push(oauthRef);
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
            // `${DB_PASS:-<pw>}`: Devin passes the text as is, the password in it
            const fallback = storedFallback(key, value);
            if (fallback !== undefined) {
              evidence.push({
                file: config.filePath,
                snippet: `mcpServers.${name}.${field}.${key}: \${…:-${mask(fallback)}}`,
                detail: `Literal secret as the default of "${key}" in MCP ${field} — Devin doesn't expand \${VAR:-default}, the server receives the text with the secret in it; use \${env:VAR} or \${file:/path} interpolation`,
              });
              continue;
            }
            const ref = unexpandedReference(value, `mcpServers.${name}.${field}.${key}`, config.filePath);
            if (ref) {
              evidence.push(ref);
              continue;
            }
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

        // Tokens on the command line (`--token ghp_…`) or in the server URL
        // (`?api_key=…`, userinfo) — the same rules as WS-003
        const args = Array.isArray(server.args) ? server.args.filter((a): a is string => typeof a === 'string') : [];
        for (const secret of findArgSecrets(args, typeof server.command === 'string' ? server.command : undefined)) {
          evidence.push({
            file: config.filePath,
            snippet: `mcpServers.${name}.${secret.location} = ${secret.masked}`,
            detail: `${cap(secret.kind)} in an MCP server argument — stored in this config and visible to any local user in the process list; use \${env:VAR} interpolation`,
          });
        }
        for (const key of ['url', 'serverUrl'] as const) {
          const url = server[key];
          if (typeof url !== 'string') continue;
          for (const secret of findUrlSecrets(url, key)) {
            evidence.push({
              file: config.filePath,
              snippet: `mcpServers.${name}.${key} = ${secret.masked}`,
              detail: `${cap(secret.kind)} in the MCP server URL — stored, logged and synced as written; use a header with \${env:VAR} interpolation`,
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
