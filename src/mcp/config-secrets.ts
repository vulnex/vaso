import { API_KEY_PATTERNS, isEnvReference, isPlaceholderSecret } from '../core/patterns.js';
import { shannonEntropy } from '../analyzers/entropy.js';

/**
 * Credentials written into an MCP server's argv or URL instead of its env
 * block: `npx server --token ghp_…`, `docker run -e GITHUB_TOKEN=ghp_… img`,
 * `mcp-remote <url> --header "Authorization: Bearer sk-…"`,
 * `https://user:pass@host`, `?api_key=…`, Telegram's `/bot<token>/`. The
 * value is never returned — only where it sits and a masked rendering.
 */
export interface ConfigSecret {
  /** `args[2]`, `url` — where the value sits. */
  location: string;
  /** What it is: a known token format, or how it was recognized. */
  kind: string;
  /** The text around the value with the value itself replaced by `***`. */
  masked: string;
  /** The raw value, for deduplication by the caller only — never print it. */
  value: string;
}

const MASK = '***';

/** Flags whose value is a credential (`--token x`, `--api-key=x`, `--password x`). */
const CREDENTIAL_FLAG = /^--?(?:[a-z][\w-]*?[-_])?(?:access[_-]?token|auth[_-]?token|token|api[_-]?key|apikey|pat|secret|client[_-]?secret|password|passwd|pwd|credentials?|bearer)$/i;
/** `NAME=value` assignment (docker `-e`, `env K=V cmd`). */
const ASSIGNMENT = /^([A-Za-z_][A-Za-z0-9_]*)=(.+)$/s;
const SECRET_VAR = /(?:token|secret|passw|pwd|credential|api[_-]?key|apikey|private[_-]?key|bearer)|(?:^|_)(?:KEY|PAT|AUTH|PASS)(?:_|$)/i;
/**
 * The header name of an `Authorization: Bearer x` / `X-Api-Key: x` argv
 * element, through its colon. The `x-` name's keyword is found by a
 * lookahead: `[\w-]*` on both sides of it backtracked over every split of a
 * long `x-keykey…` run (quadratic).
 */
const HEADER_NAME = /^\s*((?:proxy-)?authorization|x-(?=[\w-]*?(?:key|token|secret|auth))[\w-]*|api[_-]?key)\s*:/i;
const HEADER_SCHEME = /^(?:bearer|basic|token|bot)/i;
const LINE_TERMINATOR = /[\n\r\u2028\u2029]/;

/**
 * `[name, value]` of a header argument, exactly as
 * `/^\s*(NAME)\s*:\s*(?:(?:bearer|basic|token|bot)\s+)?(.+?)\s*$/i` would
 * capture them, in linear time: that regex's lazy value retried `\s*$` over
 * the rest of the text at every character (`authorization: x` + 90 000
 * spaces + `x`: seconds). Its backtracking order is followed: the longest
 * leading whitespace first, a scheme word with its longest whitespace before
 * none, then shorter leading whitespace; at each start the value is the
 * shortest that leaves only whitespace after it.
 */
export function headerArg(arg: string): [string, string] | undefined {
  const head = HEADER_NAME.exec(arg);
  if (!head) return undefined;
  const r = arg.slice(head[0].length);
  const n = r.length;
  const ws = (i: number): boolean => /\s/.test(r[i]);
  let lastNonWs = n - 1;
  while (lastNonWs >= 0 && ws(lastNonWs)) lastNonWs--;
  // first line terminator at or after each index
  const nextLT = new Int32Array(n + 1);
  nextLT[n] = n;
  for (let i = n - 1; i >= 0; i--) nextLT[i] = LINE_TERMINATOR.test(r[i]) ? i : nextLT[i + 1];
  // a value can start at t: one character of the line, everything after it whitespace
  const value = (t: number): string | undefined => {
    if (t >= n || LINE_TERMINATOR.test(r[t]) || lastNonWs >= nextLT[t]) return undefined;
    return r.slice(t, nextLT[t]).trimEnd() || r[t];
  };
  let lead = 0;
  while (lead < n && ws(lead)) lead++;
  const scheme = HEADER_SCHEME.exec(r.slice(lead, lead + 6));
  if (scheme) {
    const w = lead + scheme[0].length;
    let end = w;
    while (end < n && ws(end)) end++;
    for (let t = end; t > w; t--) {
      const v = value(t);
      if (v !== undefined) return [head[1], v];
    }
  }
  for (let t = lead; t >= 0; t--) {
    const v = value(t);
    if (v !== undefined) return [head[1], v];
  }
  return undefined;
}
/** Query parameters that carry a credential. */
const SECRET_PARAM = /^(?:access[_-]?token|auth[_-]?token|token|api[_-]?key|apikey|key|secret|client[_-]?secret|password|pass|pwd|sig|signature|private[_-]?token|jwt|bearer)$/i;

const KNOWN = API_KEY_PATTERNS.filter(p => !/assignment/i.test(p.name));

/** A value that is a reference, a placeholder, or a file path — never a stored secret. */
function notASecret(value: string): boolean {
  const v = value.trim().replace(/^['"]|['"]$/g, '');
  if (v === '') return true;
  if (isEnvReference(v) || isPlaceholderSecret(v)) return true;
  // A reference inside the value (`Bearer ${TOKEN}`, `${HOME}/key`) holds nothing literal
  if (/\$\{[^}]+\}|\$env:|\{env:[^}]+\}|%[A-Za-z_][A-Za-z0-9_]*%/i.test(v)) return true;
  // A file holding the credential (`--credentials ~/.config/x.json`), not the credential
  if (/^(?:~|\.{1,2})?[/\\]|^[A-Za-z]:[/\\]/.test(v)) return true;
  return false;
}

/** The known token format a value is (or contains), with the matched token. */
function knownToken(text: string): { name: string; token: string } | undefined {
  for (const { pattern, name } of KNOWN) {
    const m = pattern.exec(text);
    // `task-runner…`, `desk-…` in a path or package name: a prefix inside a word isn't a token prefix
    if (m && m.index > 0 && /[A-Za-z0-9]/.test(text[m.index - 1])) continue;
    if (!m || isPlaceholderSecret(m[0])) continue;
    // Patterns stop at their spec'd shape (`xoxb-<n>-<n>`); the token runs on
    // to the next delimiter, and every byte of it is masked
    const tail = /^[A-Za-z0-9_\-.~+$=]*/.exec(text.slice(m.index + m[0].length))?.[0] ?? '';
    return { name, token: m[0] + tail };
  }
  return undefined;
}

/**
 * A value that a credential flag or name labels a secret: long enough and
 * random-looking. `--api-key prod` or `--token=default` name a profile, not a key.
 */
function looksLikeSecret(value: string): boolean {
  if (value.length < 12 || /\s/.test(value)) return false;
  if (!/[A-Za-z]/.test(value) || !/[0-9]/.test(value)) return value.length >= 20 && shannonEntropy(value) > 3.5;
  return shannonEntropy(value) > 3;
}

/** `text` with every copy of `value` replaced; just the mask when the value isn't found verbatim. */
function maskIn(text: string, value: string): string {
  return text.includes(value) ? text.split(value).join(MASK) : MASK;
}

/** Secrets in one URL: userinfo, credential query parameters, token path segments. */
export function findUrlSecrets(url: string, location = 'url'): ConfigSecret[] {
  const out: ConfigSecret[] = [];
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return out;
  }
  if (!/^(?:https?|wss?):$/.test(parsed.protocol)) return out;
  const add = (value: string, kind: string) => {
    if (!value || notASecret(value) || out.some(s => s.value === value)) return;
    out.push({ location, kind, masked: maskIn(url, value), value });
  };

  // Userinfo read from the raw text: the parser percent-encodes `${PASS}`
  const userinfo = /^[a-z][a-z0-9+.-]*:\/\/([^/?#]*)@/i.exec(url)?.[1];
  if (userinfo) {
    const colon = userinfo.indexOf(':');
    const user = colon < 0 ? userinfo : userinfo.slice(0, colon);
    const password = colon < 0 ? '' : userinfo.slice(colon + 1);
    const known = knownToken(password || user);
    if (password) add(password, known ? `${known.name} as URL password` : 'password in URL userinfo');
    else if (known) add(user, `${known.name} as URL userinfo`);
    else if (user.length >= 20 && looksLikeSecret(user)) add(user, 'token as URL userinfo');
  }

  for (const [name, value] of parsed.searchParams) {
    const known = knownToken(value);
    if (known) {
      add(rawParam(url, name) ?? value, `${known.name} in URL query parameter "${name}"`);
    } else if (SECRET_PARAM.test(name) && value.length >= 8) {
      add(rawParam(url, name) ?? value, `credential in URL query parameter "${name}"`);
    }
  }

  for (const segment of parsed.pathname.split('/')) {
    if (!segment) continue;
    // Telegram Bot API: https://api.telegram.org/bot<id>:<secret>/method
    const bot = /^bot(\d{6,}:[A-Za-z0-9_-]{30,})$/.exec(segment);
    if (bot) { add(bot[1], 'Telegram Bot token in URL path'); continue; }
    const known = knownToken(segment);
    if (known) add(known.token, `${known.name} in URL path`);
  }
  return out;
}

/** The raw (still percent-encoded) value of a query parameter, so masking finds it in the URL text. */
function rawParam(url: string, name: string): string | undefined {
  const q = url.indexOf('?');
  if (q < 0) return undefined;
  for (const pair of url.slice(q + 1).split('#')[0].split(/[&;]/)) {
    const eq = pair.indexOf('=');
    if (eq < 0) continue;
    let n = pair.slice(0, eq);
    try { n = decodeURIComponent(n.replace(/\+/g, ' ')); } catch { /* keep raw */ }
    if (n === name) return pair.slice(eq + 1);
  }
  return undefined;
}

/** Secrets in an argv array: credential flags (both `--f v` and `--f=v`), env assignments, header args, URLs, bare tokens. */
export function findArgSecrets(args: readonly string[]): ConfigSecret[] {
  const out: ConfigSecret[] = [];
  const add = (i: number, value: string, kind: string, text = args[i]) => {
    if (!value || notASecret(value) || out.some(s => s.value === value)) return;
    out.push({ location: `args[${i}]`, kind, masked: maskIn(text, value), value });
  };

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    const prev = i > 0 ? args[i - 1] : undefined;

    // `--token <value>`: the value is the next element
    if (prev && CREDENTIAL_FLAG.test(prev) && !arg.startsWith('-')) {
      const known = knownToken(arg);
      if (known) add(i, known.token, `${known.name} after ${prev}`, `${prev} ${arg}`);
      else if (looksLikeSecret(arg)) add(i, arg, `credential after ${prev}`, `${prev} ${arg}`);
      continue;
    }

    // `--token=<value>`
    const flagEq = /^(--?[A-Za-z][\w-]*)=(.+)$/s.exec(arg);
    if (flagEq && CREDENTIAL_FLAG.test(flagEq[1])) {
      const known = knownToken(flagEq[2]);
      if (known) add(i, known.token, `${known.name} in ${flagEq[1]}`);
      else if (looksLikeSecret(flagEq[2])) add(i, flagEq[2], `credential in ${flagEq[1]}`);
      continue;
    }

    // `--header "Authorization: Bearer <value>"` (mcp-remote, supergateway)
    const header = headerArg(arg);
    if (header) {
      const [name, value] = header;
      const known = knownToken(value);
      if (known) add(i, known.token, `${known.name} in ${name} header argument`);
      else if (looksLikeSecret(value)) add(i, value, `credential in ${name} header argument`);
      continue;
    }

    // `-e GITHUB_TOKEN=<value>` / `env OPENAI_API_KEY=<value> node server.js`
    const assign = ASSIGNMENT.exec(arg);
    if (assign && !/^[a-z]+:\/\//i.test(arg)) {
      const known = knownToken(assign[2]);
      if (known) add(i, known.token, `${known.name} in ${assign[1]}=`);
      else if (SECRET_VAR.test(assign[1]) && looksLikeSecret(assign[2])) add(i, assign[2], `credential in ${assign[1]}=`);
      continue;
    }

    // A URL argument (`mcp-remote https://…?key=…`)
    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(arg)) {
      for (const s of findUrlSecrets(arg, `args[${i}]`)) {
        if (!out.some(o => o.value === s.value)) out.push(s);
      }
      continue;
    }

    // A bare token standing alone or inside a larger argument
    const known = knownToken(arg);
    if (known) add(i, known.token, known.name);
  }
  return out;
}
