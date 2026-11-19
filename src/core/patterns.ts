import { shannonEntropy } from '../analyzers/entropy.js';

// Quantifiers use {N,} (open-ended) rather than {N} so longer-than-spec tokens
// still match in full. With a fixed {N} bound, redaction silently leaks the
// trailing bytes when a token is longer than expected; with a trailing \b, the
// match fails entirely and the whole token slips through unredacted.
export const API_KEY_PATTERNS = [
  // Current OpenAI keys carry a scope segment and may contain - and _.
  { pattern: /sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,}/, name: 'OpenAI API key' },
  { pattern: /sk-or-v1-[a-f0-9]{32,}/, name: 'OpenRouter API key' },
  { pattern: /sk-[a-zA-Z0-9]{20,}/, name: 'OpenAI API key' },
  { pattern: /sk-ant-[a-zA-Z0-9-]{20,}/, name: 'Anthropic API key' },
  { pattern: /AKIA[0-9A-Z]{16,}/, name: 'AWS Access Key' },
  { pattern: /ghp_[a-zA-Z0-9]{36,}/, name: 'GitHub PAT' },
  { pattern: /gho_[a-zA-Z0-9]{36,}/, name: 'GitHub OAuth token' },
  { pattern: /glpat-[a-zA-Z0-9\-_]{20,}/, name: 'GitLab PAT' },
  // xoxb-<team>-<bot>-<secret>: every segment is part of the token
  { pattern: /xoxb-[0-9]+(?:-[0-9a-zA-Z]+)+/, name: 'Slack Bot token' },
  { pattern: /xoxp-[0-9]+(?:-[0-9a-zA-Z]+)+/, name: 'Slack User token' },
  { pattern: /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/, name: 'Private key' },
  { pattern: /\b[0-9]{10}:[A-Za-z0-9_-]{35,}\b/, name: 'Telegram Bot token' },
  // Live Devin CLI 3000.x credentials.toml tokens: `devin-` + ~180 chars incl. `$ . -`
  { pattern: /\bdevin-[A-Za-z0-9$._-]{60,}/, name: 'Devin API token' },
  { pattern: /\bcog_[a-zA-Z0-9]{16,}/, name: 'Devin API token (cog_)' },
  { pattern: /\bapk_(?:user_)?[a-zA-Z0-9]{16,}/, name: 'Devin API key (legacy)' },
  // Vault ≥ 1.10 service/batch/recovery tokens: hvs./hvb./hvr. + ≥ 24 chars
  // (developer.hashicorp.com/vault/docs/concepts/tokens)
  { pattern: /\bhv[sbr]\.[A-Za-z0-9_-]{24,}/, name: 'HashiCorp Vault token' },
  // Vellum keys have no documented prefix — match by env-var assignment only.
  { pattern: /VELLUM_API_KEY\s*[=:]\s*['"]?[a-zA-Z0-9._-]{20,}/, name: 'Vellum API key assignment' },
];

/** A placeholder word set off by delimiters, as documentation writes them:
 *  `sk-ant-your-actual-key-here`, `ghp_your_token`, `<your-api-key>`. A
 *  random key doesn't contain a hyphen- or underscore-delimited word. */
const PLACEHOLDER_WORD =
  /(?:^|[-_.\s<{:/])(?:your|example|sample|dummy|placeholder|changeme|change[-_]me|replace|insert|redacted|fake)(?=$|[-_.\s>}])/i;

/**
 * Whether a value that looks like a credential is a documentation
 * placeholder instead: placeholder words (above), an ellipsis (`sk-ant-...`,
 * `sk-…here`), `<…>` / `{{…}}`, or runs of x/* masking. Shared by every
 * plaintext-secret check, so docs examples copied into configs and memory
 * files aren't reported as leaked keys.
 */
export function isPlaceholderSecret(value: string): boolean {
  const v = value.trim();
  if (v === '') return true;
  if (/\.{3}|\u2026/.test(v)) return true;
  if (/^<[^>]*>$|^\{\{[^}]*\}\}$/.test(v)) return true;
  if (/x{4,}|X{4,}|\*{3,}/.test(v)) return true;
  if (/EXAMPLE(?:KEY)?$/.test(v)) return true; // AWS docs: AKIAIOSFODNN7EXAMPLE
  return PLACEHOLDER_WORD.test(v);
}

/**
 * How an agent config refers to a value kept elsewhere instead of storing it.
 * Each agent expands its own forms (verified 2026-10-15):
 *  - Claude Code `.mcp.json`: `${VAR}`, `${VAR:-default}` (code.claude.com/docs/en/mcp)
 *  - Gemini CLI / Qwen Code settings: `$VAR`, `${VAR}`, `${VAR:-default}` (geminicli.com/docs/reference/configuration)
 *  - Devin CLI, Windsurf/Devin Desktop: `${env:VAR}`, `${file:/path}` only (docs.devin.ai/cli/extensibility/mcp/configuration)
 *  - Cursor `mcp.json`: `${env:NAME}` only (cursor.com/docs/mcp)
 *  - OpenCode: `{env:VAR}`, `{file:path}` only (opencode.ai/docs/config)
 * A form the agent doesn't expand reaches the server as literal text — a
 * broken config, not a stored credential.
 */
export type EnvReferenceForm = 'env-colon' | 'brace-env' | 'dollar-brace' | 'dollar' | 'powershell' | 'percent' | 'name';

const AUTH_SCHEME_PREFIX = /^\s*(?:Bearer|Basic|Token)\s+/i;
/** UPPER_SNAKE, lower_snake, or camel/Pascal words with trailing digits — how variables are named. */
const VARIABLE_NAME = /^(?:[A-Z_][A-Z0-9_]*|[a-z_][a-z0-9_]*|[A-Za-z]?[a-z]+(?:[A-Z][a-z]+)*\d*)$/;
const ENV_REFERENCE_FORMS: Array<[EnvReferenceForm, RegExp]> = [
  ['env-colon', /^\$\{(?:env|file):[^}]+\}$/],
  ['brace-env', /^\{(?:env|file):[^}]+\}$/],
  ['dollar-brace', /^\$\{[A-Za-z_][A-Za-z0-9_]*(?::?[-=?+][^}]*)?\}$/],
  ['dollar', /^\$[A-Za-z_][A-Za-z0-9_]*$/],
  ['powershell', /^\$env:[A-Za-z_][A-Za-z0-9_]*$/i],
  ['percent', /^%[A-Za-z_][A-Za-z0-9_]*%$/],
  // Just a variable's NAME (`GITHUB_TOKEN`): upper snake case with at least
  // one underscore — no generated key looks like that
  ['name', /^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$/],
];

/**
 * The reference form when a value (after an optional `Bearer `/`Basic `/
 * `Token ` scheme) is wholly a reference to an environment variable or file,
 * never a stored credential; undefined for anything else, including a
 * literal secret written beside a reference.
 */
export function envReference(value: string): EnvReferenceForm | undefined {
  const v = value.replace(AUTH_SCHEME_PREFIX, '').trim();
  if (v === '' || v.length > 256) return undefined;
  const form = ENV_REFERENCE_FORMS.find(([, re]) => re.test(v))?.[0];
  if (form === 'name' && (v.length > 64 || API_KEY_PATTERNS.some(p => p.pattern.test(v)))) return undefined;
  // `$Zx8f3kq…` is a password that starts with `$`, not a variable: whether
  // or not the agent expands `$` forms (Claude Desktop expands none), only a
  // name shaped like a variable makes the value a reference
  const name = form && form !== 'name' && form !== 'env-colon' && form !== 'brace-env'
    ? /[A-Za-z_][A-Za-z0-9_]*/.exec(v.replace(/^\$env:/i, ''))?.[0]
    : undefined;
  if (name !== undefined && !VARIABLE_NAME.test(name)) return undefined;
  // `${VAR:-default}`: a credential written as the default is stored all the same
  const fallback = form === 'dollar-brace' ? /^\$\{[A-Za-z_][A-Za-z0-9_]*:?[-=?+](.*)\}$/.exec(v)?.[1] : undefined;
  if (fallback && !isPlaceholderSecret(fallback)
    && (API_KEY_PATTERNS.some(p => p.pattern.test(fallback)) || /^(?=.*[A-Za-z])(?=.*\d)[^\s/]{16,}$/.test(fallback))) return undefined;
  return form;
}

/** A reference to a variable or file (any agent's syntax), not a stored secret. */
export function isEnvReference(value: string): boolean {
  return envReference(value) !== undefined;
}

/**
 * Where a secret is kept, written in place of the secret: a secret manager's
 * reference, which the server or a wrapper (`op run`, `vals`, the platform)
 * resolves at start —
 *  - 1Password `op://vault/item/field`; HashiCorp Vault `vault:secret/data/x#k`,
 *    `vault://…`; vals `ref+vault://…`, `ref+awssecrets://…`, `ref+sops://…`
 *  - AWS `arn:aws:secretsmanager:<region>:<acct>:secret:<name>`,
 *    `arn:aws:ssm:<region>:<acct>:parameter/<name>`
 *  - GCP Secret Manager `projects/<p>/secrets/<name>[/versions/<v>]`
 *  - Azure Key Vault `https://<vault>.vault.azure.net/secrets/<name>`,
 *    App Service `@Microsoft.KeyVault(SecretUri=…)`
 *  - SOPS-encrypted values `ENC[AES256_GCM,data:…]`, keychain/keyring and
 *    other secret-store schemes (`keychain:name`, `doppler://…`, `bws://…`)
 * Not OpenSSL's `pass:<password>`: that is the password itself.
 */
const SECRET_MANAGER_REFERENCE = new RegExp([
  String.raw`^(?:op|vault|keychain|keyring|secret|secrets|gopass|lpass|bw|bws|doppler|infisical|azkv|gcpsm|awssm|sm|ssm|kms|sops|age)(?::\/\/|:)[^\s]+$`,
  String.raw`^ref\+[a-z0-9]+:\/\/\S+$`,
  String.raw`^arn:aws[\w-]*:(?:secretsmanager|ssm|kms):[\w-]*:\d*:\S+$`,
  String.raw`^projects\/[\w.-]+\/secrets\/[\w.-]+(?:\/versions\/[\w.-]+)?$`,
  String.raw`^https:\/\/[\w-]+\.vault\.(?:azure\.net|azure\.cn|usgovcloudapi\.net)\/secrets\/[\w-]+(?:\/\w+)?\/?$`,
  String.raw`^@Microsoft\.KeyVault\(.+\)$`,
  String.raw`^ENC\[[A-Z0-9_]+,data:.*\]$`,
].join('|'), 'i');

const PATH_PREFIX = /^(?:~|\.{1,2})?[/\\]|^[A-Za-z]:[/\\]/;

/**
 * A segment no one names a directory or file: 12+ characters of base64 /
 * base62 in both cases with digits, near-maximal entropy, that doesn't split
 * into words (`MyProject2024`, `Package-Name_Version2`).
 */
function randomSegment(segment: string): boolean {
  const s = segment.replace(/\.[A-Za-z0-9]{1,8}$/, ''); // `<random>.pem` is still random
  if (s.length < 12 || !/^[A-Za-z0-9+=_-]+$/.test(s)) return false;
  if (!/[A-Z]/.test(s) || !/[a-z]/.test(s) || !/\d/.test(s)) return false;
  if (s.split(/[-_]/).every(p => /^(?:[A-Z]?[a-z]{2,}|[A-Z]{2,}(?![a-z])|\d+)*$/.test(p))) return false;
  return shannonEntropy(s) >= Math.min(4, Math.log2(s.length) - 0.8);
}

/** A segment that names something: a word, a dotfile, a word with an extension (`.ssh`, `Users`, `id_rsa`, `key.pem`). */
const WORD_SEGMENT = /^\.?(?:[a-z]{2,}|[A-Z][a-z]+|[A-Z]{2,})(?:[._-][A-Za-z0-9]+)*$/;

/**
 * Whether a value that starts like a path (`/`, `./`, `../`, `~/`, `C:\`)
 * is one, judged by its shape: a base64 secret starts with `/` one time in
 * 64 (AWS secret keys, generated passwords), and a path is made of names. A
 * value with a random segment is a path only when it also has named
 * segments around it (`/Users/me/.keys/Xq7Lk2Pz9Rt4Vw8Y.pem`).
 */
export function isPathValue(value: string): boolean {
  const v = value.trim();
  if (!PATH_PREFIX.test(v)) return false;
  const segments = v.replace(PATH_PREFIX, '').split(/[/\\]+/).filter(Boolean);
  if (!segments.some(randomSegment)) return true;
  return segments.length >= 3 && segments.some(s => WORD_SEGMENT.test(s));
}

/** A file holding the credential: a path, or a key/config file's name (`service-account-key.json`). */
const FILE_REFERENCE = /^(?:~|\.{1,2})?[/\\]|^[A-Za-z]:[/\\]|^[\w.@-]+\.(?:json|pem|key|p8|p12|pfx|crt|cer|der|jks|keystore|txt|env|ya?ml|toml|ini|cfg|conf|gpg|asc|age|enc)$/i;

/** Words a profile, environment or region name is built from (`production-us-east-2`). */
const PROFILE_WORDS = new Set(['prod', 'production', 'staging', 'stage', 'stg', 'dev', 'development', 'test', 'testing', 'qa', 'uat',
  'sandbox', 'default', 'local', 'main', 'primary', 'secondary', 'preview', 'demo', 'personal', 'work', 'team', 'org', 'admin',
  'readonly', 'ro', 'rw', 'profile', 'region', 'global', 'us', 'eu', 'ap', 'sa', 'ca', 'me', 'af', 'il', 'cn', 'gov',
  'east', 'west', 'north', 'south', 'central', 'northeast', 'southeast', 'northwest', 'southwest']);

/**
 * A profile, environment or region name (`production-us-east-2`,
 * `default`, `my-team-1`) selecting stored credentials: lowercase words and
 * short numbers, at least one of them a profile word. A
 * passphrase of ordinary words (`correct-horse-battery-staple-9`) is not one.
 */
function isProfileName(v: string): boolean {
  if (v.length > 64 || !/^[a-z][a-z0-9]*(?:[-_.][a-z0-9]+)*$/.test(v)) return false;
  const parts = v.split(/[-_.]/);
  if (!parts.every((p) => /^[a-z]{1,16}$/.test(p) || /^\d{1,4}$/.test(p))) return false;
  return parts.some((p) => PROFILE_WORDS.has(p));
}

/**
 * A value that names where a credential is kept instead of holding it: an
 * environment/file reference (`isEnvReference`), a secret manager reference,
 * a file path or key file name, or a profile name. Shared by every place
 * VASO judges a configured value (MCP env blocks and headers, argv flags,
 * URLs, agent settings), so the same text is judged the same wherever it is
 * written. A value with a known token format is never a reference.
 */
export function isSecretReference(value: string): boolean {
  const v = value.replace(AUTH_SCHEME_PREFIX, '').trim().replace(/^(['"])(.*)\1$/, '$2');
  if (v === '') return false;
  if (isEnvReference(v)) return true;
  if (API_KEY_PATTERNS.some((p) => p.pattern.test(v))) return false;
  // a value that only starts like a path (`/Xq7Lk2Pz9…`, a base64 secret) is
  // judged by its shape; the probe's Go copy does the same
  return SECRET_MANAGER_REFERENCE.test(v) || FILE_REFERENCE.test(v) && (!PATH_PREFIX.test(v) || isPathValue(v)) || isProfileName(v);
}

/**
 * `isSecretReference`, with a value that only starts like a path judged by
 * its shape (`isPathValue`): `/Xq7Lk2Pz9…` is a base64 secret, not a file.
 * (`isSecretReference` itself has a Go copy in the probe and stays as is.)
 */
export function isCredentialReference(value: string): boolean {
  if (!isSecretReference(value)) return false;
  const v = value.replace(AUTH_SCHEME_PREFIX, '').trim().replace(/^(['"])(.*)\1$/, '$2');
  return !PATH_PREFIX.test(v) || isEnvReference(v) || isPathValue(v);
}

export const OAUTH_SECRET_PATTERNS = [
  { pattern: /^client_secret$/i, name: 'OAuth client secret (key name)' },
  { pattern: /^oauth[_-]?(?:client[_-]?)?secret$/i, name: 'OAuth secret (key name)' },
  { pattern: /^(?:access|refresh)[_-]?token$/i, name: 'OAuth token (key name)' },
  { pattern: /^oauth[_-]?(?:access|refresh)?[_-]?token$/i, name: 'OAuth token (key name)' },
  { pattern: /^authorization[_-]?code$/i, name: 'OAuth authorization code (key name)' },
];

export const OAUTH_TOKEN_VALUE_PATTERNS = [
  { pattern: /^ya29\.[a-zA-Z0-9_-]+/, name: 'Google OAuth access token' },
  { pattern: /^eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+$/, name: 'JWT bearer token' },
  { pattern: /^ory_at_[a-zA-Z0-9_-]+/, name: 'Ory OAuth access token' },
];

/**
 * How evidence names a plaintext secret it found: its length, no character of
 * it. A quoted prefix (`DB_PASSWORD=Tr0ub4do…`) gave away most of a short
 * secret, and the report masker reads a trailing `…` as a placeholder
 * (`sk-ant-…`), so it printed it in every format.
 */
export function secretShape(value: string, kind?: string): string {
  // the kind inside the brackets: before them, the report masker read its
  // first word as the value (`token: *** PAT <literal, 40 chars>`)
  return kind ? `<literal, ${value.length} chars, ${kind}>` : `<literal, ${value.length} chars>`;
}

/**
 * A recognised token as evidence prints it: its length and kind, no
 * character of it (`<literal, 40 chars, GitHub PAT>`). The first and last
 * four characters it used to keep were 8 of a short token's characters.
 */
export function redactSecret(token: string, kind?: string): string {
  return secretShape(token, kind);
}

function withGlobalFlag(pattern: RegExp): RegExp {
  return pattern.flags.includes('g')
    ? pattern
    : new RegExp(pattern.source, pattern.flags + 'g');
}

/** Longest evidence snippet a result keeps (engine capSnippets; reports again after masking). */
export const MAX_SNIPPET = 300;

/** Characters that end a value in a config or source line. */
const VALUE_BOUNDARY = /[\s"'`,;:=(){}[\]<>]/;
/** The most of a value cut by truncation a snippet keeps. */
const CUT_VALUE_KEEP = 8;

/**
 * A snippet cut to `maxLen` characters. A value the cut falls inside keeps at
 * most its first 8 characters, and the marker is set off by a space: an
 * ellipsis glued to the value made `"db_password":"Zp9Yx8…` read as a
 * placeholder (`sk-ant-...`) to the report masker, which then printed it.
 */
export function truncateSnippet(text: string, maxLen = 80): string {
  if (text.length <= maxLen) return text;
  let cut = text.slice(0, maxLen);
  if (!VALUE_BOUNDARY.test(text[maxLen])) {
    let start = cut.length;
    while (start > 0 && !VALUE_BOUNDARY.test(cut[start - 1])) start--;
    cut = cut.slice(0, Math.min(cut.length, start + CUT_VALUE_KEEP));
  }
  return `${cut} ...`;
}

/** Characters of context kept before a match by snippetAround. */
const CONTEXT_BEFORE = 40;

/**
 * The part of a long line around a match at `index` (length `length`), cut
 * like truncateSnippet at both ends: a value the start falls inside is
 * skipped rather than shown in part, and the cut is marked `... `. A short
 * line is returned whole (trimmed). For minified or one-line files, where the
 * matching "line" is the whole file.
 */
export function snippetAround(line: string, index: number, length: number, maxLen = 120): string {
  const text = line.trim();
  const offset = line.length - line.trimStart().length;
  if (text.length <= maxLen) return text;
  const at = Math.max(0, index - offset);
  let start = Math.max(0, at - CONTEXT_BEFORE);
  if (start > 0 && !VALUE_BOUNDARY.test(text[start - 1])) {
    // don't begin inside a value: move to just after the next boundary before the match
    let s = start;
    while (s < at && !VALUE_BOUNDARY.test(text[s])) s++;
    start = s < at ? s + 1 : at;
  }
  const keep = Math.max(maxLen, at - start + length + CONTEXT_BEFORE);
  return `${start > 0 ? '... ' : ''}${truncateSnippet(text.slice(start), keep)}`;
}

/** `text` with every recognised token replaced by its kind and length. */
function redactTokens(text: string): string {
  let redacted = text;
  for (const { pattern, name } of API_KEY_PATTERNS) {
    redacted = redacted.replace(withGlobalFlag(pattern), (m) => redactSecret(m, name));
  }
  return redacted;
}

export function redactSecretsInLine(line: string, maxLen = 80): string {
  return truncateSnippet(redactTokens(line).trim(), maxLen);
}

/**
 * redactSecretsInLine around the match at `index` (length `length`): in a
 * one-line (minified) file the line is the whole file, and a snippet from
 * its start quoted whatever values came first, not the match.
 */
export function redactSecretsAround(line: string, index: number, length: number, maxLen = 80): string {
  const before = redactTokens(line.slice(0, index));
  const at = redactTokens(line.slice(index, index + length));
  return snippetAround(before + at + redactTokens(line.slice(index + length)), before.length, at.length, maxLen);
}
