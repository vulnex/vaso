import { API_KEY_PATTERNS, isEnvReference, isPlaceholderSecret, isSecretReference } from '../core/patterns.js';
import { findUrlSecrets } from '../mcp/config-secrets.js';
import { shannonEntropy } from './entropy.js';

/**
 * Whether a configured value is a stored credential: the judgement behind
 * the agent-settings checks (GEM-001, QC-001, CC-004) and the keyed lines
 * of the memory-file scan. Two arms:
 *  - a recognised token format, under any name (`isKnownSecretValue`);
 *  - under a credential name, a long random-looking value
 *    (`isSecretNamedValue`): mixed letters and digits, a hex key ≥ 32
 *    characters or a UUID-shaped one (Heroku, Langfuse `sk-lf-<uuid>`).
 * Neither arm takes a reference (`$VAR`, `op://…`, an ARN, a file), a
 * placeholder, a public key or an OAuth client ID.
 */

/**
 * Token formats `API_KEY_PATTERNS` leaves out (that list has a Go mirror in
 * the probe; these are judged on the scanning side only).
 */
export const EXTRA_TOKEN_PATTERNS: RegExp[] = [
  /^github_pat_[A-Za-z0-9_]{20,}/,
  /^gh[ousr]_[A-Za-z0-9]{30,}/,
  /^sk-or-v1-[A-Za-z0-9]{32,}/,
  /^sk-ant-[A-Za-z0-9_-]{20,}/,
  /^sk-ak-[A-Za-z0-9]{20,}/, // Zapier MCP
  /^sk-lf-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i, // Langfuse secret key
  /^xox[abeprs]-[A-Za-z0-9-]{10,}/,
  /^AIza[0-9A-Za-z_-]{30,}/,
  /^ASIA[0-9A-Z]{16,}/,
  /^gsk_[A-Za-z0-9]{20,}/,
  /^hf_[A-Za-z0-9]{20,}/,
  /^xai-[A-Za-z0-9]{32,}/,
  /^nvapi-[A-Za-z0-9_-]{20,}/,
  /^glpat-[A-Za-z0-9_-]{20,}/,
  /^pat[A-Za-z0-9]{14}\.[0-9a-f]{64}/, // Airtable personal access token
];

/**
 * Values that are public by design though they sit under a `*_KEY`/`*_AUTH`
 * name: SSH/age public keys, PEM public keys and certificates, Google OAuth
 * client IDs, Stripe publishable and Langfuse public keys.
 */
const PUBLIC_VALUE = new RegExp([
  String.raw`^(?:ssh-(?:rsa|dss|ed25519)|ecdsa-sha2-nistp\d+|sk-(?:ssh-ed25519|ecdsa-sha2-nistp256)@openssh\.com)\s+AAAA`,
  String.raw`^-----BEGIN (?:(?:RSA |EC )?PUBLIC KEY|CERTIFICATE)-----`,
  String.raw`\.apps\.googleusercontent\.com$`,
  String.raw`^age1[0-9a-z]{50,}$`,
  String.raw`^pk_(?:live|test)_`,
  String.raw`^pk-lf-`,
].join('|'));

/**
 * Credential-word names that hold something other than the credential:
 * `OAUTH_CLIENT_ID`, `AUTH_URL`, `TOKEN_ENDPOINT`, `*_SECRET_ARN`,
 * `API_KEY_FILE`, `SESSION_KEY_PREFIX`, `SSH_PUBLIC_KEY`, `STRIPE_PUBLISHABLE_KEY`,
 * `PASSWORD_HASH`, `KEY_FINGERPRINT` (a salt stays secret).
 */
const NON_SECRET_NAME = /(?:^|[_.-])(?:hash|hashed|digest|fingerprint|checksum|id|ids|url|uri|endpoint|host|hostname|domain|arn|file|path|dir|prefix|suffix|name|user|username|email|region|header|type|mode|scope|scopes|ttl|expiry|expires)$|public|publishable/i;

/** `…-<uuid>` (or a bare UUID): a key minted as a UUID. */
const UUID_TAIL = /(?:^|[-_])[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * A password hash or content digest, not the secret: modular crypt
 * (`$2b$12$…`, `bcrypt$2b$…`, `$argon2id$…`, `$scrypt$…`, `pbkdf2_sha256$…`,
 * `$6$…`) or `sha256:<hex>`.
 */
const HASHED_VALUE = /^(?:[a-z][\w-]*\$)?\$?(?:2[abxy]?|argon2(?:id|i|d)?|scrypt|pbkdf2[\w-]*|[156y]|sha(?:256|512)-?crypt)\$|^(?:sha(?:1|224|256|384|512)|md5|blake2b?)[:=-][0-9a-f]{32,}$/i;

/** A password hash or digest (`$2b$12$…`, `sha256:<hex>`). */
export function isHashedValue(value: string): boolean {
  return HASHED_VALUE.test(value.trim());
}

/** Placeholder, reference (variable, secret manager, file, profile) or public value: never a stored secret. */
function notStored(value: string): boolean {
  return isPlaceholderSecret(value) || isEnvReference(value) || isSecretReference(value) || PUBLIC_VALUE.test(value) || isHashedValue(value);
}

/** Whether a credential-word name holds the credential itself (not its ID, URL, file or public half). */
export function isCredentialValueName(name: string): boolean {
  return !NON_SECRET_NAME.test(name);
}

/**
 * Random-looking: no whitespace, at least `minLength` long, and a hex key
 * (≥ 32), a UUID-shaped key, or letters with digits whose entropy is near
 * the most its length allows. A 20-character random key can't reach a fixed
 * 4.5 bits (log2 20 = 4.3), so the bar scales with the length. A word with
 * one version digit (`gemini-session-cache-v2`) is not random.
 */
export function looksRandom(value: string, minLength = 16): boolean {
  if (value.length < minLength || /\s/.test(value)) return false;
  if (/^(?=.*[a-f])[0-9a-f]{32,}$|^(?=.*[A-F])[0-9A-F]{32,}$/.test(value)) return true;
  if (UUID_TAIL.test(value)) return true;
  const entropy = shannonEntropy(value);
  // an alphabet-rich value without digits (`wJalrXUtnFEMI/K7…` has some; base64 may not)
  if (value.length >= 20 && entropy > 4.5) return true;
  const digits = value.replace(/\D/g, '').length;
  const upper = /[A-Z]/.test(value);
  const lower = /[a-z]/.test(value);
  if (digits === 0 || !(upper || lower)) return false;
  // single-case: a bare base36 run (`a8f3k2m9q…`), not words joined by
  // punctuation (`max_tokens=4096`, `cache-v2`)
  if (!(upper && lower) && (!/^[a-z0-9]+$/i.test(value) || digits < 3 || value.length - digits < 3)) return false;
  return entropy >= Math.min(4.5, Math.log2(value.length) - 0.7);
}

/** A recognised token format (or a URL carrying one), whatever name it is stored under. */
export function isKnownSecretValue(value: string): boolean {
  const v = value.trim();
  if (v === '' || notStored(v)) return false;
  if (API_KEY_PATTERNS.some(({ pattern }) => pattern.test(v)) || EXTRA_TOKEN_PATTERNS.some(p => p.test(v))) return true;
  return /^https?:\/\//i.test(v) && findUrlSecrets(v).some(s => !isTenantSegment(v, s.value));
}

/**
 * Microsoft identity platform authorities (`https://login.microsoftonline.com/<tenant>/v2.0`):
 * the tenant id in the first path segment is public — any sign-in page shows it.
 */
const AUTHORITY_HOST = /^(?:login\.microsoftonline\.(?:com|us|de)|login\.partner\.microsoftonline\.cn|login\.chinacloudapi\.cn|login\.windows\.net|login\.microsoft\.com|sts\.windows\.net)$/i;

function isTenantSegment(url: string, value: string): boolean {
  try {
    const u = new URL(url);
    return AUTHORITY_HOST.test(u.hostname) && u.pathname.split('/')[1] === value;
  } catch {
    return false;
  }
}

/** A value under a credential name (`GITLAB_TOKEN`, `MISTRAL_KEY`) that is the credential itself. */
export function isSecretNamedValue(name: string, value: string): boolean {
  const v = value.trim();
  if (v === '' || notStored(v)) return false;
  if (isKnownSecretValue(v)) return true;
  // A URL is judged by the credentials in it (findUrlSecrets above), not by
  // how random the whole string looks: a tenant or resource id in its path
  // is not the credential the name promises
  if (/^https?:\/\//i.test(v)) return false;
  return isCredentialValueName(name) && looksRandom(v);
}
