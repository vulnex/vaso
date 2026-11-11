import { join } from 'node:path';
import { parseTomlSafe } from '../../core/toml-safe.js';
import type { ParsedConfig, ScanContext } from '../../core/types.js';
import { asRecord } from './zc-config.js';
import { isEnvReference, isPlaceholderSecret } from '../../core/patterns.js';

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
]);
/** Tables whose every string value is a secret (`[http_request.secrets]`). */
const SECRET_MAPS = new Set(['secrets']);

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
    out.push({ filePath: c.filePath, raw: c.raw, data: c.data, main: isMain(c) });
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

function isMain(c: ParsedConfig): boolean {
  return c.format === 'toml' && /(^|[\\/])config\.toml$/.test(c.filePath);
}
