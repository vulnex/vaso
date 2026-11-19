/**
 * Credentials hardcoded in MCP server source (MCP-003's source half). The
 * config half looks at `env`/`headers` values; a key compiled into the server
 * — `headers: { "X-Api-Key": "bjlY…" }` — ships to everyone who installs it.
 *
 * Three signals, judged per statement (see sourceSegments): a known token
 * format, a secret-named key/header assigned a high-entropy literal, and a
 * literal `Bearer …` value. Placeholders, env-var names, identifiers and URLs
 * are not secrets. Evidence carries only a masked prefix — reports must never
 * repeat the credential.
 */

import { API_KEY_PATTERNS, isPlaceholderSecret, secretShape } from '../core/patterns.js';
import { shannonEntropy } from './entropy.js';
import { EXTRA_TOKEN_PATTERNS } from './secret-values.js';
import { sourceSegments } from '../mcp/source-segments.js';

export interface SourceSecret {
  line: number;
  /** What it is: a token format name, or "secret-named value". */
  kind: string;
  /** The key/header name it was assigned to, when there is one. */
  key?: string;
  /** First characters and length only. */
  masked: string;
  /** The code next to it says the value is public by design (author's claim). */
  declaredPublic?: boolean;
}

/**
 * Values vendors publish for everyone to use, so shipping them leaks
 * nothing. Exact values only, each with its source.
 */
const DOCUMENTED_PUBLIC_VALUES = new Set([
  // QStash local development server, test user 1 — base64 of
  // {"UserID":"defaultUser","Password":"defaultPassword"}
  // https://upstash.com/docs/qstash/howto/local-development
  'eyJVc2VySUQiOiJkZWZhdWx0VXNlciIsIlBhc3N3b3JkIjoiZGVmYXVsdFBhc3N3b3JkIn0=',
]);

/** An author's note that a key is meant to be public (a telemetry/ingest or publishable key). */
const DECLARED_PUBLIC = /\b(?:public by design|(?:is|are) (?:intentionally |meant to be )?public|publishable key|not a secret)\b/i;
/** Comment lines looked at above a value. */
const COMMENT_WINDOW = 6;

/**
 * `"X-Api-Key": "…"`, `apiKey = '…'`, `CLIENT_SECRET: "…"` — key, then a
 * quoted value. A name starts at the first letter of its `a-b-c` run that
 * begins a word: a later one (the lookbehind) can only match what that one
 * already tried, and retrying the run from each `-` was quadratic.
 */
const KEYED_LITERAL =
  /["']?\b(?=[A-Za-z_])(?<!(?:^|[^\w])[A-Za-z_][\w-]*?)([A-Za-z_][\w-]*)(?![\w-])["']?\s*[:=]\s*(?:[\w$.]{1,120}(?:\([^()"'`\n]{0,80}(?:["'][\w.-]{1,64}["'][^()"'`\n]{0,20})?\)|\[["'][\w.-]{1,64}["']\])?\s*(?:\?\?|\|\||\bor\b)\s*)?["'`]([^"'`\s]{16,})["'`]/gi;
/**
 * The default of an environment lookup — `os.getenv("API_KEY", "…")`,
 * `os.environ.get("DB_PASSWORD", "…")` — is stored in the source all the same.
 */
const ENV_DEFAULT =
  /\b(?:getenv|environ\.get|env\.get)\(\s*["']([A-Za-z_]\w{0,80})["']\s*,\s*["']([^"'\s]{16,})["']/gi;

/** Name parts that are a credential: `secret`, `apiToken` → `token`, `dbPass` → `pass`. */
const CREDENTIAL_PART = /^(?:\w*(?:apikey|secret|token|password|passwd|accesskey|privatekey|credential)s?|pass|passphrase|passcode)$/;
/** Parts before a trailing `key` that make it a lookup, index or public key, not a secret one. */
const NOT_SECRET_KEY = new Set([
  'public', 'publishable', 'pub', 'foreign', 'sort', 'partition', 'cache', 'idempotency', 'storage', 'dedupe',
  'dedup', 'row', 'unique', 'lookup', 'map', 'object', 'query', 'route', 'translation', 'i18n', 'message', 'label', 'state',
  'item', 'entry', 'field', 'prop', 'attr', 'event', 'index', 'column', 'table', 'hash', 'site', 'list', 'group', 'schema',
  'local', 'shortcut', 'hot', 'keyboard', 'cursor', 'page', 'node', 'element', 'component', 'react', 'redis', 'kv', 'store',
  'bucket', 'file', 'config', 'setting', 'settings', 'option', 'metadata', 'meta', 'header', 'sub', 'parent', 'child', 'next',
  'prev', 'last', 'first', 'id', 'name', 'type', 'path', 'url', 'env', 'context', 'data', 'request', 'response', 'lock', 'job',
  'queue', 'task', 'user', 'session', 'feature', 'flag', 'shard', 'sharding', 'asset', 'deduplication',
  'routing', 'buster', 'composite', 'surrogate',
  // analytics ingest keys, public by design (Segment write keys, Application Insights instrumentation keys)
  'write', 'insights', 'instrumentation', 'analytics', 'telemetry', 'ingest', 'ingestion', 'tracking', 'measurement',
  // client-side product-analytics project keys, shipped in every web page by design
  'posthog', 'segment', 'mixpanel', 'amplitude',
]);
/**
 * Parts before a trailing `key` that name a lookup key as often as a
 * credential: Azure ships credential pairs as primary/secondary keys, a
 * tenant or namespace key can be either. Such a name holds a credential when
 * its value is opaque key material (`opaqueValue`), not a path or a name.
 */
const MAYBE_SECRET_KEY = new Set(['primary', 'secondary', 'tenant', 'namespace', 'model', 's3']);
/** Parts before a `token` that make it an LLM/pagination token, not a credential: `maxTokens`, `nextPageToken`. */
const NOT_SECRET_TOKEN = new Set([
  'max', 'min', 'num', 'total', 'output', 'prompt', 'completion', 'reasoning', 'cached', 'page', 'next',
  'prev', 'continuation', 'cursor', 'pagination', 'bos', 'eos', 'pad', 'unk', 'sep', 'cls', 'mask', 'special', 'stop',
]);
/** Parts before a `token` that name an LLM or sync token as often as a credential; judged as MAYBE_SECRET_KEY. */
const MAYBE_SECRET_TOKEN = new Set(['input', 'context', 'sync']);
/** Last parts that describe a credential rather than hold one: `secretName`, `tokenUrl`, `API_KEY_ENV`. */
const DESCRIPTIVE_PART = new Set([
  'name', 'names', 'path', 'paths', 'file', 'files', 'url', 'urls', 'uri', 'endpoint', 'length', 'len', 'type', 'types', 'id',
  'ids', 'header', 'headers', 'env', 'var', 'vars', 'field', 'fields', 'prefix', 'suffix', 'label', 'format', 'pattern',
  'regex', 're', 'count', 'size', 'hint', 'placeholder', 'description', 'desc', 'title', 'location', 'dir', 'param', 'params',
  'policy', 'expiry', 'expires', 'ttl', 'timeout', 'limit', 'max', 'min', 'strength', 'validator', 'schema', 'input', 'kind',
  'mode', 'source', 'provider', 'scope', 'scopes', 'hash', 'help', 'message', 'msg', 'error', 'required', 'enabled', 'store',
  'storage', 'cache', 'arn', 'ref', 'reference', 'version', 'handle', 'uuid', 'guid', 'resource', 'region', 'account', 'link', 'route',
  'regexp', 'patterns', 'formats', 'fingerprint', 'fingerprints', 'metric', 'metrics',
]);
/**
 * Last parts that describe a credential's shape or use as often as they name
 * one holding it: `TOKEN_CHARS`, `PASSWORD_RULE`, `AUTH_TOKEN_COOKIE`,
 * `secretFlag`. The name holds a credential when its value is opaque key
 * material; a charset (every character once), a rule or a cookie name is not.
 */
const MAYBE_DESCRIPTIVE_PART = new Set([
  'char', 'chars', 'characters', 'charset', 'alphabet', 'strings', 'delimiter', 'delimiters', 'separator', 'separators',
  'rule', 'rules', 'cookie', 'cookies', 'flag', 'flags', 'usage',
]);
/** MAYBE_DESCRIPTIVE_PART entries naming a set of characters. */
const CHARSET_PART = new Set(['char', 'chars', 'characters', 'charset', 'alphabet', 'strings', 'delimiter', 'delimiters', 'separator', 'separators']);
/** Parts before a last `key` naming where a credential is kept: `TOKEN_KEY`, `PASSWORD_STORAGE_KEY`. */
const STORED_UNDER = new Set(['token', 'tokens', 'password', 'passwd', 'pass', 'credential', 'credentials', 'storage', 'store', 'cache', 'cookie', 'session', 'local']);
/** First parts that make the name a flag or a question: `isSecret`, `hasPassword`. */
const PREDICATE_PART = new Set(['is', 'has', 'have', 'should', 'use', 'uses', 'require', 'requires', 'need', 'needs', 'show', 'hide', 'no', 'without', 'enable', 'disable', 'allow', 'can']);

/** `apiKeyV2` → [api, key, v2]; `client_secret_key` → [client, secret, key]; `password2` → [password, 2]. */
function nameParts(name: string): string[] {
  return name
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1 $2')
    .replace(/([A-Za-z])(\d)/g, '$1 $2')
    .split(/[\s_\-.]+/)
    .filter(Boolean)
    .map((p) => p.toLowerCase());
}

/**
 * How a key/variable name relates to a credential:
 * - `credential`: it holds one — a credential word anywhere in it
 *   (`SECRET_KEY`, `secret_key_base`, `password2`, `dbPass`, `privateKeyPem`),
 *   or a `…Key` qualified by something other than a lookup or public key
 *   (`signingKey`, `stripeKey`, `apiKeyV2`);
 * - `opaque`: it holds one only when the value is opaque key material
 *   (`secondaryKey`, `TENANT_KEY`, `contextToken`, `AUTH_TOKEN_COOKIE`,
 *   `TOKEN_CHARS`);
 * - undefined: it describes one (`secretName`, `tokenUrl`, `API_KEY_ENV`,
 *   `isSecret`) or is no credential at all.
 * `charset` marks a name that may hold a set of characters (`TOKEN_CHARS`);
 * `word` that a credential word (not just a `…Key`) named it.
 */
interface SecretName { kind: 'credential' | 'opaque'; charset: boolean; word: boolean }

function secretName(name: string): SecretName | undefined {
  const parts = nameParts(name);
  if (parts.length === 0) return undefined;
  if (parts.length > 1 && PREDICATE_PART.has(parts[0])) return undefined;
  // a trailing number or version names a variant, not a role: `secretKeyFormat2`, `apiKeyV2`, `password2`
  let end = parts.length - 1;
  while (end > 0 && /^(?:v?\d+|v)$/.test(parts[end])) end--;
  const last = parts[end];
  for (let i = 0; i <= end; i++) {
    const part = parts[i];
    // `S3_KEY` → [s, 3, key]: the qualifier is `s3`
    const qualifier = i > 1 && /^\d+$/.test(parts[i - 1]) ? parts[i - 2] + parts[i - 1] : parts[i - 1];
    const keyed = (part === 'key' || part === 'keys') && i > 0 && !NOT_SECRET_KEY.has(qualifier);
    const word = CREDENTIAL_PART.test(part);
    if (!keyed && !word) continue;
    const tokenPart = part === 'token' || part === 'tokens';
    if (tokenPart && i > 0 && NOT_SECRET_TOKEN.has(parts[i - 1])) continue;
    // what follows the credential word names something about it: `tokenUrl`,
    // and `TOKEN_KEY` / `TOKEN_STORAGE_KEY`, the key a token is stored under
    if (i < end && DESCRIPTIVE_PART.has(last)) return undefined;
    if (i < end && (last === 'key' || last === 'keys') && STORED_UNDER.has(parts[end - 1])) return undefined;
    const maybe = (keyed && !word && MAYBE_SECRET_KEY.has(qualifier))
      || (tokenPart && i > 0 && MAYBE_SECRET_TOKEN.has(parts[i - 1]))
      || (i < end && MAYBE_DESCRIPTIVE_PART.has(last));
    return { kind: maybe ? 'opaque' : 'credential', charset: i < end && CHARSET_PART.has(last), word };
  }
  return undefined;
}

/** Whether a key/variable name holds a credential whatever its value looks like (see secretName). */
export function isSecretKeyName(name: string): boolean {
  return secretName(name)?.kind === 'credential';
}
const BEARER_LITERAL = /["'`]Bearer\s+([A-Za-z0-9._~+/=-]{20,})["'`]/g;
/**
 * Credentials inside a command line or URL string, where no quoted
 * key/value pair surrounds them: a URL's userinfo password
 * (`https://u:<pw>@`, `redis://:<pw>@`), an `Authorization:` header value
 * inside a curl command, a `PGPASSWORD=<pw>` prefix, a MySQL/sshpass `-p`.
 */
const URL_PASSWORD = /\b[a-z][a-z0-9+.-]{1,31}:\/\/[^\s:@/"'`]*:([^\s@/"'`]{6,})@/gi;
const AUTH_HEADER_VALUE = /\bAuthorization\s*:\s*(?:Bearer|Basic|Token)\s+([A-Za-z0-9._~+/=-]{16,})/gi;
const ENV_ASSIGNED = /\b([A-Z][A-Z0-9_]*(?:PASSWORD|PASSWD|TOKEN|SECRET|API_KEY|APIKEY))=([^\s"'`$;&|]{12,})/g;
const PASSWORD_FLAG = /\b(?:mysql\w*|mariadb\w*|sshpass)\b[^"'`\n]{0,200}?\s-p\s?([^\s"'`]{8,})/g;

/** PEM header followed by key material, not a format constant in a crypto library. */
const PRIVATE_KEY_BLOCK = /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----(?:\\n|\s)+[A-Za-z0-9+/=]{64}/;

/**
 * Token formats found anywhere in a statement — in a URL query (`?key=AIza…`),
 * a constructor argument, a `??` fallback: `API_KEY_PATTERNS` plus the
 * scanner-side `EXTRA_TOKEN_PATTERNS` (unanchored here) and two formats only
 * source scanning looks for (Stripe secret/restricted keys, SendGrid keys).
 */
const TOKEN_NAMES: Array<[string, string]> = [
  ['github_pat_', 'GitHub fine-grained PAT'], ['gh', 'GitHub token'], ['sk-or-v1-', 'OpenRouter API key'],
  ['sk-ant-', 'Anthropic API key'], ['sk-ak-', 'Zapier MCP key'], ['sk-lf-', 'Langfuse secret key'],
  ['xox', 'Slack token'], ['AIza', 'Google API key'], ['ASIA', 'AWS temporary access key'], ['gsk_', 'Groq API key'],
  ['hf_', 'Hugging Face token'], ['xai-', 'xAI API key'], ['nvapi-', 'NVIDIA API key'], ['glpat-', 'GitLab PAT'],
  ['pat', 'Airtable personal access token'],
];
export const SOURCE_TOKEN_PATTERNS: Array<{ pattern: RegExp; name: string }> = [
  ...EXTRA_TOKEN_PATTERNS.map((p) => {
    const body = p.source.replace(/^\^/, '');
    const anchoredEnd = body.endsWith('$');
    return {
      pattern: new RegExp(`(?<![A-Za-z0-9_])${anchoredEnd ? `${body.slice(0, -1)}(?![A-Za-z0-9_-])` : body}`, p.flags.replace('g', '')),
      name: TOKEN_NAMES.find(([prefix]) => body.startsWith(prefix))?.[1] ?? 'API token',
    };
  }),
  { pattern: /(?<![A-Za-z0-9_])[sr]k_live_[A-Za-z0-9]{24,}/, name: 'Stripe secret key' },
  { pattern: /(?<![A-Za-z0-9_])SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}(?![A-Za-z0-9_-])/, name: 'SendGrid API key' },
];

const PLACEHOLDER = /your|example|sample|dummy|placeholder|changeme|replace|insert|redacted|xxxx|\*{3}|<[^>]*>|\$\{|\{\{|%s/i;
const MIN_ENTROPY = 3.8;

/** Regular-expression constructs: a character class, a group construct, an escape class, a quantifier. */
const REGEX_CONSTRUCT = /(?:\[[^\]]{1,80}\]|\((?:\?[=!:<])?[^()]{0,80}\)|\\[dwsDWSb.])(?:[+*?]|\{\d+(?:,\d*)?\})?|\{\d+(?:,\d*)?\}/g;
/**
 * Regular-expression text, not a password that happens to hold a bracket or a
 * `\d`: anchored at both ends, three constructs or more, or constructs
 * (a class, a group, an escape, each with its quantifier) making up half of it.
 */
function regexShaped(value: string): boolean {
  if (/^\^.*\$$/.test(value) && /[[\\({+*?]/.test(value)) return true;
  let count = 0;
  let covered = 0;
  for (const m of value.matchAll(REGEX_CONSTRUCT)) {
    count++;
    covered += m[0].length;
  }
  return count >= 3 || (count > 0 && covered / value.length >= 0.5);
}
/** Public half of a key pair: PEM/OpenSSH public keys, base64 DER SubjectPublicKeyInfo. */
const PUBLIC_KEY_VALUE =
  /^(?:-----BEGIN (?:RSA )?PUBLIC KEY|ssh-(?:rsa|ed25519|dss)\b|ecdsa-sha2-|MCowBQYDK2V[uw]|MEMwBQYDK2Vx|MEIwBQYDK2Vv|MFkwEwYHKoZIzj0CAQ|MHYwEAYHKoZIzj0CAQ|MIGbMBAGByqGSM49AgE|MI[A-Za-z0-9+/]{2,6}(?:BgkqhkiG9w0BAQEFAAO|CSqGSIb3DQEBAQUAA4))/;
/** A key fingerprint (`SHA256:…`), published to let others check the key. */
const FINGERPRINT_VALUE = /^(?:SHA(?:1|256|384|512)|MD5):/i;

/**
 * Share of a value made of ascending runs (`abcdefgh`, `0123456789`) of three or
 * more: an alphabet or charset constant, not random key material.
 */
function sequentialShare(value: string): number {
  let covered = 0;
  let run = 1;
  for (let i = 1; i <= value.length; i++) {
    if (i < value.length && value.charCodeAt(i) === value.charCodeAt(i - 1) + 1) { run++; continue; }
    if (run >= 3) covered += run;
    run = 1;
  }
  return covered / value.length;
}

/** Keys published for local emulators: the Azurite / Azure Storage Emulator account key. */
const PUBLIC_EMULATOR_KEYS = new Set([
  'Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==',
]);
/** Lowercase or uppercase hex of 32+ characters with letters and digits: a key, a token, a digest. */
const HEX_MATERIAL = /^(?=[0-9a-f]*[a-f])(?=[0-9a-f]*\d)[0-9a-f]{32,}$|^(?=[0-9A-F]*[A-F])(?=[0-9A-F]*\d)[0-9A-F]{32,}$/;
/** A part made of words and numbers (`Settings2Secondary9Label`, `gpt4oMini20240718Preview`, `User123`). */
const WORDS = /^(?:[A-Z]?[a-z]{2,}|[A-Z]{2,}(?![a-z])|\d+[a-z]?)+$/;

/**
 * Opaque key material, not a path, a name or a model id: hex (32+), base64
 * or base64url in mixed case with digits, a dotted token (`<a>.<b>.<c>`,
 * JWT-shaped), or a single-case random run (32+, letters and digits).
 * Words and numbers joined (`Settings2Secondary9Label`, model ids with a
 * date) and object-key paths (`uploads/User123/avatar2024`) are names.
 */
function opaqueValue(value: string, charset: boolean): boolean {
  if (PUBLIC_EMULATOR_KEYS.has(value)) return false;
  // a character set lists every character once; random key material repeats some
  if (charset && new Set(value).size === value.length) return false;
  if (HEX_MATERIAL.test(value)) return true;
  if (/^[a-z0-9]{32,}$|^[A-Z0-9]{32,}$/.test(value)) {
    const digits = value.replace(/\D/g, '').length;
    return digits >= 4 && value.length - digits >= 4 && shannonEntropy(value) >= 4;
  }
  const segments = value.split('.');
  if (segments.length > 3 || !segments.every((seg) => /^[A-Za-z0-9+/_-]{8,}={0,2}$/.test(seg)) || value.length < 16) return false;
  if (!/[a-z]/.test(value) || !/[A-Z]/.test(value) || !/\d/.test(value)) return false;
  // words, numbers and short parts joined: a name, a path, a cookie name (`__Host-csrf-token-v2`)
  return !value.split(/[-_./+=]+/).filter(Boolean).every((part) => WORDS.test(part) || part.length <= 4);
}

/** A value under a name: whether it is a credential the name holds (see secretName). */
function namedSecretValue(name: SecretName, value: string): boolean {
  // `SHA256:…` is a key's fingerprint under a `…Key` name, never under `apiSecret`
  if (!name.word && FINGERPRINT_VALUE.test(value)) return false;
  if (PUBLIC_EMULATOR_KEYS.has(value)) return false;
  // hex is at most 4 bits a character: under a lookup-or-credential name it is judged by its shape, not the entropy floor
  const hex = name.kind !== 'credential' && HEX_MATERIAL.test(value) && !PLACEHOLDER.test(value) && sequentialShare(value) < 0.6;
  if (!looksLikeSecretValue(value) && !hex) return false;
  return name.kind === 'credential' || opaqueValue(value, name.charset);
}

function looksLikeSecretValue(value: string): boolean {
  if (PLACEHOLDER.test(value)) return false;
  // an env-var name: API_KEY: "OPENAI_API_KEY" (a 32+ run with no `_` is a random uppercase token)
  if (/^[A-Z][A-Z0-9_]+$/.test(value) && !(value.length >= 32 && !value.includes('_'))) return false;
  if (/^(?:[a-z]+|[a-z]+(?:[A-Z][a-z0-9]+)+|[A-Z][a-z]+(?:[A-Z][a-z0-9]+)*)$/.test(value)) return false; // identifier
  if (/^(?:https?:)?\/\/|^[./~]/.test(value)) return false; // URL or path
  if (/^(.)\1+$/.test(value)) return false;
  if (regexShaped(value) || PUBLIC_KEY_VALUE.test(value)) return false;
  if (sequentialShare(value) >= 0.6) return false;
  if (!/[A-Za-z]/.test(value) || !/\d/.test(value)) return false;
  return shannonEntropy(value) >= MIN_ENTROPY;
}

function mask(value: string): string {
  return secretShape(value);
}

export function findSourceSecrets(code: string): SourceSecret[] {
  return collectSourceSecrets(code).map((f) => f.secret);
}

/**
 * The raw values findSourceSecrets flags in `code` — for masking them where
 * another check quotes the same source (never put these in evidence).
 */
export function findSourceSecretValues(code: string): string[] {
  return [...new Set(collectSourceSecrets(code).map((f) => f.value).filter((v) => v !== PEM_MARK))];
}

const PEM_MARK = '\0pem';

function collectSourceSecrets(code: string): Array<{ secret: SourceSecret; value: string }> {
  const found: Array<{ secret: SourceSecret; value: string }> = [];
  const seen = new Set<string>();
  const lines = code.split('\n');
  const commentAbove = (line: number): string =>
    lines.slice(Math.max(0, line - 1 - COMMENT_WINDOW), line).filter(l => /^\s*(?:\/\/|\/?\*|#)/.test(l)).join(' ');
  const add = (secret: SourceSecret, value: string): void => {
    const id = `${secret.line}\0${value}`;
    if (seen.has(id) || DOCUMENTED_PUBLIC_VALUES.has(value)) return;
    seen.add(id);
    if (DECLARED_PUBLIC.test(commentAbove(secret.line))) secret.declaredPublic = true;
    found.push({ secret, value });
  };

  for (const { line, text } of sourceSegments(code)) {
    const tokens: string[] = [];
    for (const { pattern, name } of API_KEY_PATTERNS) {
      if (name === 'Private key') {
        if (PRIVATE_KEY_BLOCK.test(text)) add({ line, kind: name, masked: '-----BEGIN … PRIVATE KEY-----' }, PEM_MARK);
        continue;
      }
      const m = pattern.exec(text);
      // an access key id is exactly AKIA + 16: a longer all-caps word (`AKIAPACIFICNORTHEAST1`) is none
      if (m && name === 'AWS Access Key' && (m[0].length !== 20 || /[A-Za-z0-9]/.test(text[m.index + 20] ?? ''))) continue;
      if (m && !PLACEHOLDER.test(m[0])) { add({ line, kind: name, masked: mask(m[0]) }, m[0]); tokens.push(m[0]); }
    }
    for (const { pattern, name } of SOURCE_TOKEN_PATTERNS) {
      const m = pattern.exec(text);
      if (!m || PLACEHOLDER.test(m[0]) || isPlaceholderSecret(m[0])) continue;
      // The same token already matched by a broader format on this statement
      if (tokens.some((t) => t.includes(m[0]) || m[0].includes(t))) continue;
      add({ line, kind: name, masked: mask(m[0]) }, m[0]);
      tokens.push(m[0]);
    }
    for (const re of [KEYED_LITERAL, ENV_DEFAULT]) {
      for (const m of text.matchAll(re)) {
        const [, key, value] = m;
        const name = secretName(key);
        if (!name || tokens.some((t) => value.includes(t))) continue;
        if (namedSecretValue(name, value)) add({ line, kind: 'secret-named value', key, masked: mask(value) }, value);
      }
    }
    for (const m of text.matchAll(BEARER_LITERAL)) {
      if (looksLikeSecretValue(m[1])) add({ line, kind: 'bearer token', key: 'Authorization', masked: mask(m[1]) }, m[1]);
    }
    for (const m of text.matchAll(AUTH_HEADER_VALUE)) {
      if (looksLikeSecretValue(m[1])) add({ line, kind: 'bearer token', key: 'Authorization', masked: mask(m[1]) }, m[1]);
    }
    for (const m of text.matchAll(URL_PASSWORD)) {
      if (looksLikeSecretValue(m[1])) add({ line, kind: 'password in URL', masked: mask(m[1]) }, m[1]);
    }
    for (const m of text.matchAll(ENV_ASSIGNED)) {
      if (looksLikeSecretValue(m[2])) add({ line, kind: 'secret-named value', key: m[1], masked: mask(m[2]) }, m[2]);
    }
    for (const m of text.matchAll(PASSWORD_FLAG)) {
      if (looksLikeSecretValue(m[1])) add({ line, kind: 'password in command', key: '-p', masked: mask(m[1]) }, m[1]);
    }
  }
  return found;
}
