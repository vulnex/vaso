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
  { pattern: /xoxb-[0-9]+-[0-9a-zA-Z]+/, name: 'Slack Bot token' },
  { pattern: /xoxp-[0-9]+-[0-9a-zA-Z]+/, name: 'Slack User token' },
  { pattern: /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/, name: 'Private key' },
  { pattern: /\b[0-9]{10}:[A-Za-z0-9_-]{35,}\b/, name: 'Telegram Bot token' },
  // Live Devin CLI 3000.x credentials.toml tokens: `devin-` + ~180 chars incl. `$ . -`
  { pattern: /\bdevin-[A-Za-z0-9$._-]{60,}/, name: 'Devin API token' },
  { pattern: /\bcog_[a-zA-Z0-9]{16,}/, name: 'Devin API token (cog_)' },
  { pattern: /\bapk_(?:user_)?[a-zA-Z0-9]{16,}/, name: 'Devin API key (legacy)' },
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

export function redactSecret(token: string): string {
  if (token.length <= 12) return `[REDACTED:${token.length}c]`;
  return `${token.slice(0, 4)}...${token.slice(-4)}`;
}

function withGlobalFlag(pattern: RegExp): RegExp {
  return pattern.flags.includes('g')
    ? pattern
    : new RegExp(pattern.source, pattern.flags + 'g');
}

export function redactSecretsInLine(line: string, maxLen = 80): string {
  let redacted = line;
  for (const { pattern } of API_KEY_PATTERNS) {
    redacted = redacted.replace(withGlobalFlag(pattern), (m) => redactSecret(m));
  }
  const trimmed = redacted.trim();
  return trimmed.length > maxLen ? trimmed.slice(0, maxLen) + '...' : trimmed;
}
