import { basename } from 'node:path';
import type { Evidence, ParsedConfig } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { isPlaceholderSecret } from '../../core/patterns.js';
import { isKnownSecretValue, isSecretNamedValue } from '../../analyzers/secret-values.js';
import { headerSecret } from '../../mcp/config-secrets.js';

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

export const ghc003 = defineCheck({
  id: 'GHC-003',
  name: 'Copilot CLI Plaintext GitHub Token or Provider Key',
  category: 'coding-agent',
  severity: 'critical',
  description: 'Scan ~/.copilot/{config,settings}.json for inline GitHub tokens (gho_, ghp_, etc.) and providers.json for plaintext BYOK API keys / bearer tokens',
  supportedAgents: ['copilot-cli'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      if (basename(config.filePath) === 'providers.json') {
        evidence.push(...providerSecrets(config));
        continue;
      }
      if (!config.raw) continue;
      for (const { pattern, name } of GITHUB_TOKEN_PATTERNS) {
        const m = pattern.exec(config.raw);
        if (m && isPlaceholderSecret(m[0])) continue;
        if (m) {
          evidence.push({
            file: config.filePath,
            snippet: `${m[0].slice(0, 8)}…`,
            detail: `Plaintext ${name} in Copilot config — rotate immediately and rely on the OS keychain or gh CLI's hosts.yml`,
          });
        }
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'No plaintext GitHub tokens or provider keys detected in Copilot CLI config files',
      failed: (n) => `Found ${n} plaintext token(s) or provider key(s) in Copilot CLI config`,
      fixDescription: 'Revoke the token at https://github.com/settings/tokens and let Copilot store auth via keychain or gh CLI; for BYOK providers keep providers.json owner-only (chmod 600), out of repositories and backups, and rotate any key that was exposed',
    });
  },
});
