import { join } from 'node:path';
import { parseTomlSafe } from '../../core/toml-safe.js';
import type { ParsedConfig, ScanContext } from '../../core/types.js';
import { asRecord } from './zc-config.js';
import { isEnvReference, isPlaceholderSecret } from '../../core/patterns.js';
import { isKnownSecretValue } from '../../analyzers/secret-values.js';
import { envOverridesOf } from '../../adapters/env-overrides.js';

/**
 * Secret-bearing field names across ZeroClaw's config (`#[secret]` fields in
 * zeroclaw-config's schema: provider api_key, reliability.api_keys, channel
 * bot/access/app tokens and signing secrets, gateway.webhook_secret, composio
 * api_key, http_request.secrets values, …) and auth-profiles.json token
 * fields. Keys are compared after camelCase → snake_case normalisation.
 */
const SECRET_KEYS = new Set([
  'api_key', 'api_keys', 'token', 'bot_token', 'app_token', 'api_token', 'auth_token',
  'access_token', 'refresh_token', 'id_token', 'oauth_token', 'bearer_token',
  'channel_access_token', 'secret', 'app_secret', 'client_secret', 'channel_secret',
  'webhook_secret', 'signing_secret', 'verify_token', 'verification_token',
  'password', 'app_password', 'smtp_password', 'sasl_password', 'server_password',
  'nickserv_password', 'private_key', 'recovery_key', 'encrypt_key', 'webhook_key',
  'auth_header', 'embedding_api_key',
  // gateway.paired_tokens: the live `zc_…` bearer tokens of paired clients;
  // TLS client keys
  'paired_tokens', 'client_key',
]);
/** Tables whose every string value is a secret (`[http_request.secrets]`). */
const SECRET_MAPS = new Set(['secrets']);
/** Header tables ZeroClaw stores as secrets (observability.otel_headers,
 *  provider extra_headers): a header naming a credential, or a value with a
 *  known token format, is one; `Content-Type` and the like are not. */
const SECRET_HEADER_MAPS = new Set(['otel_headers', 'extra_headers']);
const CREDENTIAL_HEADER = /auth|token|key|secret|cookie|passw/i;
/** Connection URLs ZeroClaw stores as secrets (memory db_url, amqp_url):
 *  a secret when they carry a password (`scheme://user:pass@host`). */
const SECRET_URL_KEYS = new Set(['db_url', 'amqp_url']);
const URL_PASSWORD = /^[a-z][a-z0-9+.-]*:\/\/[^/@\s:]*:[^/@\s]+@/i;

function normaliseKey(k: string): string {
  return k.replace(/([a-z0-9])([A-Z])/g, '$1_$2').replace(/-/g, '_').toLowerCase();
}

function isSecretKey(k: string): boolean {
  const n = normaliseKey(k);
  return SECRET_KEYS.has(n) || n.endsWith('_api_key');
}

/** A stored value is protected when it is ChaCha20 (`enc2:`), legacy XOR
 *  (`enc:`), a 1Password ref, or a `${VAR}` reference resolved from the
 *  environment at load time. */
export function isProtectedSecret(v: string): boolean {
  return v.startsWith('enc2:') || v.startsWith('enc:') || v.startsWith('op://') || /^\$\{[A-Za-z_][A-Za-z0-9_]*\}$/.test(v);
}

export interface PlaintextSecret {
  path: string;
}

/** Dotted paths of plaintext (unencrypted, non-reference) secret values. */
export function findPlaintextSecrets(data: unknown): PlaintextSecret[] {
  const out: PlaintextSecret[] = [];
  const visit = (node: unknown, path: string, secretCtx: boolean, depth: number): void => {
    if (depth > 12 || node === null || node === undefined) return;
    if (typeof node === 'string') {
      const v = node.trim();
      if (secretCtx && v !== '' && !isProtectedSecret(v) && !isPlaceholderSecret(v) && !isEnvReference(v)) out.push({ path });
      return;
    }
    if (Array.isArray(node)) {
      node.forEach((item, i) => visit(item, `${path}[${i}]`, secretCtx, depth + 1));
      return;
    }
    const rec = asRecord(node);
    if (!rec) return;
    for (const [k, v] of Object.entries(rec)) {
      const p = path ? `${path}.${k}` : k;
      const n = normaliseKey(k);
      if (SECRET_HEADER_MAPS.has(n) && asRecord(v)) {
        for (const [header, value] of Object.entries(asRecord(v)!)) {
          if (typeof value !== 'string') continue;
          const val = value.trim();
          if (val === '' || isProtectedSecret(val) || isPlaceholderSecret(val) || isEnvReference(val)) continue;
          if (CREDENTIAL_HEADER.test(header) || isKnownSecretValue(val)) out.push({ path: `${p}.${header}` });
        }
        continue;
      }
      if (SECRET_URL_KEYS.has(n) && typeof v === 'string') {
        if (URL_PASSWORD.test(v.trim()) && !isProtectedSecret(v.trim())) out.push({ path: p });
        continue;
      }
      const secret = secretCtx || isSecretKey(k) || (SECRET_MAPS.has(k) && asRecord(v) !== undefined);
      visit(v, p, secret, depth + 1);
    }
  };
  visit(data, '', false, 0);
  return out;
}

export interface SecretSource {
  filePath: string;
  raw: string;
  data: Record<string, unknown>;
  /** The live config.toml (fix target), as opposed to a backup or auth store. */
  main: boolean;
}

/**
 * Every file that can carry ZeroClaw secrets: config.toml and
 * auth-profiles.json (loaded as configs), plus the V1/V2→V3 migration
 * backup `config.toml.backup` read directly — it keeps the pre-migration
 * secrets but is not a live config, so it is never loaded for generic checks.
 */
export async function secretSources(ctx: ScanContext): Promise<SecretSource[]> {
  const out: SecretSource[] = [];
  for (const c of ctx.configs) {
    if (c.format !== 'toml' && c.format !== 'json') continue;
    out.push({ filePath: c.filePath, raw: c.raw, data: fileData(c), main: isMain(c) });
  }
  const backup = join(ctx.installation.installDir, 'config.toml.backup');
  try {
    if (await ctx.fs.access(backup)) {
      const raw = await ctx.fs.readFile(backup);
      let data: Record<string, unknown> = {};
      try {
        data = parseTomlSafe(raw);
      } catch {}
      out.push({ filePath: backup, raw, data, main: false });
    }
  } catch {}
  return out;
}

/**
 * The values the file itself holds: config.toml data carries the
 * ZEROCLAW_<path> overlay (env-overrides.ts), and a secret the environment
 * supplies is not stored in the file — the environment is the safe place for
 * it. The file's own text is re-read for those.
 */
function fileData(c: ParsedConfig): Record<string, unknown> {
  if (envOverridesOf(c.data).length === 0 || c.format !== 'toml') return c.data;
  try {
    return parseTomlSafe(c.raw);
  } catch {
    return c.data;
  }
}

function isMain(c: ParsedConfig): boolean {
  return c.format === 'toml' && /(^|[\\/])config\.toml$/.test(c.filePath);
}
