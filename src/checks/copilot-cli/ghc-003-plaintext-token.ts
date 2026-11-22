import { basename } from 'node:path';
import type { Evidence, ParsedConfig } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { isPlaceholderSecret, secretShape } from '../../core/patterns.js';
import { isKnownSecretValue, isSecretNamedValue } from '../../analyzers/secret-values.js';
import { findArgSecrets, findUrlSecrets, headerSecret } from '../../mcp/config-secrets.js';

const GITHUB_TOKEN_PATTERNS = [
  { pattern: /\bgho_[A-Za-z0-9]{20,}/, name: 'GitHub OAuth token' },
  { pattern: /\bghp_[A-Za-z0-9]{20,}/, name: 'GitHub personal access token' },
  { pattern: /\bghs_[A-Za-z0-9]{20,}/, name: 'GitHub server token' },
  { pattern: /\bghu_[A-Za-z0-9]{20,}/, name: 'GitHub user-to-server token' },
  { pattern: /\bghr_[A-Za-z0-9]{20,}/, name: 'GitHub refresh token' },
  { pattern: /\bgithub_pat_[A-Za-z0-9_]{20,}/, name: 'GitHub fine-grained PAT' },
];

/**
 * providers.json (bring-your-own-key registry): `providers[].apiKey`,
 * `bearerToken` and `headers.<name>` are stored as plain text, and `$VAR`
 * is a literal string, not an environment reference (config-dir reference,
 * "providers.json"). A key for a local unauthenticated server is simply
 * absent.
 */
function providerSecrets(config: ParsedConfig): Evidence[] {
  const out: Evidence[] = [];
  const providers = Array.isArray(config.data.providers) ? config.data.providers : [];
  providers.forEach((p, i) => {
    if (!p || typeof p !== 'object') return;
    const rec = p as Record<string, unknown>;
    const label = typeof rec.name === 'string' ? rec.name : `#${i}`;
    for (const field of ['apiKey', 'bearerToken'] as const) {
      const v = rec[field];
      if (typeof v !== 'string' || !(isSecretNamedValue('API_KEY', v) || isKnownSecretValue(v))) continue;
      out.push({
        file: config.filePath,
        snippet: `providers["${label}"].${field} (literal value, ${v.trim().length} chars)`,
        detail: `Plaintext provider ${field === 'apiKey' ? 'API key' : 'bearer token'} in providers.json — anyone who can read the file (or a copy of it) can use the key`,
      });
    }
    const headers = rec.headers;
    if (headers && typeof headers === 'object' && !Array.isArray(headers)) {
      for (const [name, v] of Object.entries(headers as Record<string, unknown>)) {
        if (typeof v !== 'string') continue;
        const kind = headerSecret(name, v);
        if (!kind) continue;
        out.push({
          file: config.filePath,
          snippet: `providers["${label}"].headers.${name} (literal value)`,
          detail: `Plaintext ${kind} in providers.json`,
        });
      }
    }
  });
  return out;
}

/**
 * MCP server definitions (~/.copilot/mcp-config.json, project .mcp.json /
 * .github/mcp.json): a credential written as a literal in `env`, `headers`,
 * `args` or the URL instead of a `$VAR` / `${VAR}` reference. A GitHub token
 * the raw scan already reported is not listed twice.
 */
function mcpServerSecrets(config: ParsedConfig, reported: Set<string>): Evidence[] {
  const out: Evidence[] = [];
  const servers = config.data.mcpServers;
  if (!servers || typeof servers !== 'object' || Array.isArray(servers)) return out;
  const seen = (v: string) => [...reported].some(r => v.includes(r));
  for (const [name, raw] of Object.entries(servers as Record<string, unknown>)) {
    if (!raw || typeof raw !== 'object') continue;
    const server = raw as Record<string, unknown>;
    const env = server.env;
    if (env && typeof env === 'object' && !Array.isArray(env)) {
      for (const [key, v] of Object.entries(env as Record<string, unknown>)) {
        if (typeof v !== 'string' || seen(v) || isPlaceholderSecret(v.trim())) continue;
        if (!(isSecretNamedValue(key, v) || isKnownSecretValue(v))) continue;
        out.push({
          file: config.filePath,
          snippet: `mcpServers.${name}.env.${key}=${secretShape(v.trim())}`,
          detail: `Plaintext secret in MCP server env "${key}" — reference an environment variable ($${key}) instead of storing the value`,
        });
      }
    }
    const headers = server.headers;
    if (headers && typeof headers === 'object' && !Array.isArray(headers)) {
      for (const [key, v] of Object.entries(headers as Record<string, unknown>)) {
        if (typeof v !== 'string' || seen(v)) continue;
        const kind = headerSecret(key, v);
        if (!kind) continue;
        out.push({
          file: config.filePath,
          snippet: `mcpServers.${name}.headers.${key} (literal value)`,
          detail: `Plaintext ${kind} in MCP server header "${key}" — reference an environment variable instead`,
        });
      }
    }
    const args = Array.isArray(server.args) ? server.args.filter((a): a is string => typeof a === 'string') : [];
    for (const secret of findArgSecrets(args, typeof server.command === 'string' ? server.command : undefined)) {
      if (seen(secret.value)) continue;
      out.push({
        file: config.filePath,
        snippet: `mcpServers.${name}.${secret.location} = ${secret.masked}`,
        detail: `${secret.kind} in an MCP server argument — stored in this config and visible to any local user in the process list`,
      });
    }
    if (typeof server.url === 'string') {
      for (const secret of findUrlSecrets(server.url, 'url')) {
        if (seen(secret.value)) continue;
        out.push({
          file: config.filePath,
          snippet: `mcpServers.${name}.url = ${secret.masked}`,
          detail: `${secret.kind} in the MCP server URL — stored and logged as written`,
        });
      }
    }
  }
  return out;
}

export const ghc003 = defineCheck({
  id: 'GHC-003',
  name: 'Copilot CLI Plaintext GitHub Token or Provider Key',
  category: 'coding-agent',
  severity: 'critical',
  description: 'Scan ~/.copilot/{config,settings}.json for inline GitHub tokens (gho_, ghp_, etc.), providers.json for plaintext BYOK API keys / bearer tokens, and MCP server env/headers/args/URLs for literal credentials',
  supportedAgents: ['copilot-cli'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      if (basename(config.filePath) === 'providers.json') {
        evidence.push(...providerSecrets(config));
        continue;
      }
      const reported = new Set<string>();
      for (const { pattern, name } of config.raw ? GITHUB_TOKEN_PATTERNS : []) {
        const m = pattern.exec(config.raw);
        if (m && isPlaceholderSecret(m[0])) continue;
        if (m) {
          reported.add(m[0]);
          evidence.push({
            file: config.filePath,
            snippet: secretShape(m[0]),
            detail: `Plaintext ${name} in Copilot config — rotate immediately and rely on the OS keychain or gh CLI's hosts.yml`,
          });
        }
      }
      evidence.push(...mcpServerSecrets(config, reported));
    }

    return h.fromEvidence(evidence, {
      passed: 'No plaintext GitHub tokens or provider keys detected in Copilot CLI config files',
      failed: (n) => `Found ${n} plaintext token(s) or provider key(s) in Copilot CLI config`,
      fixDescription: 'Revoke the token at https://github.com/settings/tokens and let Copilot store auth via keychain or gh CLI; for BYOK providers keep providers.json owner-only (chmod 600), out of repositories and backups, and rotate any key that was exposed',
    });
  },
});
