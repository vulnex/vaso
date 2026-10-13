import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { API_KEY_PATTERNS } from '../../core/patterns.js';
import { accessibleByOthers, queryPermissions } from '../../core/permissions.js';
import { asRecord, atomicConfigs, llmProviders, mask, mcpServers, serverName } from './shared.js';

// Upstream keeps secrets in <stateDir>/.env (written 0600) and references them
// by name (`apiKeyEnvVar`, `apiKeyEnv`, `tokenEnv`). These config.json fields
// take literal values instead — and config.json is written with no explicit
// mode, so it follows the umask (typically 0644/0664).
const SECRET_KEY_HINT = /(KEY|TOKEN|SECRET|PASS|AUTH|COOKIE)/i;
const AUTH_SCHEME = /^\s*(?:Bearer|Basic|Token)\b\s*/i;
const MIN_SECRET_LENGTH = 8;

function knownTokenName(value: string): string | undefined {
  return API_KEY_PATTERNS.find(p => p.pattern.test(value))?.name;
}

/** Secret-looking entries of a string map (env / headers). */
function secretEntries(map: unknown): Array<[string, string, string | undefined]> {
  const out: Array<[string, string, string | undefined]> = [];
  for (const [key, value] of Object.entries(asRecord(map) ?? {})) {
    if (typeof value !== 'string') continue;
    const literal = value.replace(AUTH_SCHEME, '').trim();
    const tokenName = knownTokenName(literal);
    if (!tokenName && !SECRET_KEY_HINT.test(key)) continue;
    if (literal.length < MIN_SECRET_LENGTH) continue;
    out.push([key, value, tokenName]);
  }
  return out;
}

export const at004 = defineCheck({
  id: 'AT-004',
  name: 'Atomic Agent Plaintext Secrets in config.json',
  category: 'atomic-agent',
  severity: 'critical',
  description: 'Literal credentials in config.json — llm.providers[].apiKey / headers, mcp.servers[].env / transport.headers, or webhooks.<name>.secret — instead of <stateDir>/.env. config.json is written without an explicit mode, is served by the HTTP API\'s /api/config, and is the file users paste into issues.',
  supportedAgents: ['atomic-agent'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    for (const config of atomicConfigs(ctx.configs)) {
      const found: Evidence[] = [];
      const file = config.filePath;

      llmProviders(config.data).forEach((p, i) => {
        const id = typeof p.id === 'string' ? p.id : `#${i}`;
        if (typeof p.apiKey === 'string' && p.apiKey.trim().length > 0) {
          found.push({
            file,
            snippet: `llm.providers[${id}].apiKey: ${mask(p.apiKey)}`,
            detail: 'Literal provider API key — move it to .env and reference it with apiKeyEnvVar',
          });
        }
        for (const [key, value, tokenName] of secretEntries(p.headers)) {
          found.push({
            file,
            snippet: `llm.providers[${id}].headers.${key}: ${mask(value)}`,
            detail: tokenName ? `Plaintext ${tokenName} in provider header "${key}"` : `Literal credential in provider header "${key}"`,
          });
        }
      });

      mcpServers(config.data).forEach((s, i) => {
        const name = serverName(s, i);
        const transport = asRecord(s.transport);
        for (const [field, map] of [['env', s.env], ['transport.headers', transport?.headers]] as const) {
          for (const [key, value, tokenName] of secretEntries(map)) {
            found.push({
              file,
              snippet: `mcp.servers[${name}].${field}.${key}: ${mask(value)}`,
              detail: tokenName ? `Plaintext ${tokenName} in MCP ${field} "${key}"` : `Literal secret-like value for "${key}" in MCP ${field}`,
            });
          }
        }
      });

      // Webhook secrets have no .env form — upstream compares the header with
      // webhooks.<name>.secret itself, and AT-008 asks for one — so they are
      // only a finding when config.json is readable by other users.
      const webhookSecrets: Evidence[] = [];
      for (const [name, hook] of Object.entries(asRecord(config.data.webhooks) ?? {})) {
        const secret = asRecord(hook)?.secret;
        if (typeof secret === 'string' && secret.length > 0) {
          webhookSecrets.push({
            file,
            snippet: `webhooks.${name}.secret: ${mask(secret)}`,
            detail: 'Webhook shared secret in a config.json other users can read',
          });
        }
      }

      if (found.length === 0 && webhookSecrets.length === 0) continue;
      // Readable by other local users → the exposure is live, not just at-rest.
      let readableMode: string | undefined;
      try {
        const perms = await queryPermissions(ctx.fs, file);
        if (perms !== 'unsupported' && accessibleByOthers(perms)) readableMode = perms.octal;
      } catch {}
      if (readableMode) {
        for (const e of found) e.detail += ` (config.json is mode 0${readableMode} — readable by other users)`;
        for (const e of webhookSecrets) e.detail += ` (mode 0${readableMode})`;
        found.push(...webhookSecrets);
      }
      evidence.push(...found);
    }
    return h.fromEvidence(evidence, {
      passed: 'No plaintext credentials in Atomic Agent config.json',
      failed: (n) => `Found ${n} plaintext credential(s) in Atomic Agent config.json`,
      fixDescription: 'Move secrets to ~/.atomic-agent/.env (chmod 600) and reference them by name (llm.providers[].apiKeyEnvVar); webhook secrets can only live in config.json — chmod 600 it; rotate any exposed credential',
    });
  },
});
