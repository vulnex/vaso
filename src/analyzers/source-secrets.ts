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

import { API_KEY_PATTERNS, isPlaceholderSecret } from '../core/patterns.js';
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
  /["']?\b(?=[A-Za-z_])(?<!(?:^|[^\w])[A-Za-z_][\w-]*?)((?:[A-Za-z_][\w-]*?)?(?:api[_-]?key|apikey|secret|token|password|passwd|access[_-]?key|private[_-]?key|credential)s?)["']?\s*[:=]\s*(?:[\w$.]{1,120}(?:\([^()"'`\n]{0,80}(?:["'][\w.-]{1,64}["'][^()"'`\n]{0,20})?\)|\[["'][\w.-]{1,64}["']\])?\s*(?:\?\?|\|\||\bor\b)\s*)?["'`]([^"'`\s]{16,})["'`]/gi;
/**
 * The default of an environment lookup — `os.getenv("API_KEY", "…")`,
 * `os.environ.get("DB_PASSWORD", "…")` — is stored in the source all the same.
 */
const ENV_DEFAULT =
  /\b(?:getenv|environ\.get|env\.get)\(\s*["']([A-Za-z_]\w{0,80}?(?:key|token|secret|password|passwd|credential)s?)["']\s*,\s*["']([^"'\s]{16,})["']/gi;
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

function looksLikeSecretValue(value: string): boolean {
  if (PLACEHOLDER.test(value)) return false;
  if (/^[A-Z][A-Z0-9_]+$/.test(value)) return false; // an env-var name: API_KEY: "OPENAI_API_KEY"
  if (/^(?:[a-z]+|[a-z]+(?:[A-Z][a-z0-9]+)+|[A-Z][a-z]+(?:[A-Z][a-z0-9]+)*)$/.test(value)) return false; // identifier
  if (/^(?:https?:)?\/\/|^[./~]/.test(value)) return false; // URL or path
  if (/^(.)\1+$/.test(value)) return false;
  if (!/[A-Za-z]/.test(value) || !/\d/.test(value)) return false;
  return shannonEntropy(value) >= MIN_ENTROPY;
}

function mask(value: string): string {
  return `${value.slice(0, 4)}… (${value.length} chars)`;
}

export function findSourceSecrets(code: string): SourceSecret[] {
  const found: SourceSecret[] = [];
  const seen = new Set<string>();
  const lines = code.split('\n');
  const commentAbove = (line: number): string =>
    lines.slice(Math.max(0, line - 1 - COMMENT_WINDOW), line).filter(l => /^\s*(?:\/\/|\/?\*|#)/.test(l)).join(' ');
  const add = (secret: SourceSecret, value: string): void => {
    const id = `${secret.line}\0${value}`;
    if (seen.has(id) || DOCUMENTED_PUBLIC_VALUES.has(value)) return;
    seen.add(id);
    if (DECLARED_PUBLIC.test(commentAbove(secret.line))) secret.declaredPublic = true;
    found.push(secret);
  };

  for (const { line, text } of sourceSegments(code)) {
    const tokens: string[] = [];
    for (const { pattern, name } of API_KEY_PATTERNS) {
      if (name === 'Private key') {
        if (PRIVATE_KEY_BLOCK.test(text)) add({ line, kind: name, masked: '-----BEGIN … PRIVATE KEY-----' }, 'pem');
        continue;
      }
      const m = pattern.exec(text);
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
        if (tokens.some((t) => value.includes(t))) continue;
        if (looksLikeSecretValue(value)) add({ line, kind: 'secret-named value', key, masked: mask(value) }, value);
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
