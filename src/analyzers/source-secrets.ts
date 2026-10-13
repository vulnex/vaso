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

import { API_KEY_PATTERNS } from '../core/patterns.js';
import { shannonEntropy } from './entropy.js';
import { sourceSegments } from '../mcp/source-segments.js';

export interface SourceSecret {
  line: number;
  /** What it is: a token format name, or "secret-named value". */
  kind: string;
  /** The key/header name it was assigned to, when there is one. */
  key?: string;
  /** First characters and length only. */
  masked: string;
}

/** `"X-Api-Key": "…"`, `apiKey = '…'`, `CLIENT_SECRET: "…"` — key, then a quoted value. */
const KEYED_LITERAL =
  /["']?\b((?:[A-Za-z_][\w-]*?)?(?:api[_-]?key|apikey|secret|token|password|passwd|access[_-]?key|private[_-]?key|credential)s?)["']?\s*[:=]\s*["'`]([^"'`\s]{16,})["'`]/gi;
const BEARER_LITERAL = /["'`]Bearer\s+([A-Za-z0-9._~+/=-]{20,})["'`]/g;
/** PEM header followed by key material, not a format constant in a crypto library. */
const PRIVATE_KEY_BLOCK = /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----(?:\\n|\s)+[A-Za-z0-9+/=]{64}/;

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
  const add = (secret: SourceSecret, value: string): void => {
    const id = `${secret.line}\0${value}`;
    if (seen.has(id)) return;
    seen.add(id);
    found.push(secret);
  };

  for (const { line, text } of sourceSegments(code)) {
    for (const { pattern, name } of API_KEY_PATTERNS) {
      if (name === 'Private key') {
        if (PRIVATE_KEY_BLOCK.test(text)) add({ line, kind: name, masked: '-----BEGIN … PRIVATE KEY-----' }, 'pem');
        continue;
      }
      const m = pattern.exec(text);
      if (m && !PLACEHOLDER.test(m[0])) add({ line, kind: name, masked: mask(m[0]) }, m[0]);
    }
    for (const m of text.matchAll(KEYED_LITERAL)) {
      const [, key, value] = m;
      if (looksLikeSecretValue(value)) add({ line, kind: 'secret-named value', key, masked: mask(value) }, value);
    }
    for (const m of text.matchAll(BEARER_LITERAL)) {
      if (looksLikeSecretValue(m[1])) add({ line, kind: 'bearer token', key: 'Authorization', masked: mask(m[1]) }, m[1]);
    }
  }
  return found;
}
