/**
 * JSON serialization for everything VASO writes out (reports, `detect` /
 * `mcp list` JSON, baselines). Scan results carry each installation's parsed
 * config files — raw text and data, plaintext secrets included — because
 * checks need them in memory. None of that may leave the process: config
 * files keep their path and format, and MCP server env/headers values are
 * masked, so a report or a baseline never becomes a copy of the user's
 * credentials (a remote scan would otherwise move the host's secrets onto
 * the scanning machine).
 */

import { isPlaceholderSecret } from '../core/patterns.js';

const MASKED_MAPS = new Set(['env', 'headers']);

function maskValue(value: string): string {
  return value.length > 8 ? `${value.slice(0, 4)}…(${value.length} chars)` : '***';
}

const MASK = '***';

/**
 * A value that is not itself a secret: a reference to one (`${VAR}`,
 * `$VAR`, `{env:VAR}`, `%VAR%`), a documentation placeholder, or already masked.
 */
function keepValue(value: string): boolean {
  const v = value.trim().replace(/^['"]|['"]$/g, '');
  if (v === '' || v === MASK) return true;
  // a file holding the credential (`--ssh-key ~/.ssh/id_rsa`), not the credential
  if (/^(?:~|\.{1,2})?\//.test(v)) return true;
  if (/^\$\{[^}]+\}$|^\$[A-Za-z_][A-Za-z0-9_]*$|^\$?\{(?:env|file):[^}]+\}$|^%[A-Za-z_][A-Za-z0-9_]*%$/.test(v)) return true;
  return isPlaceholderSecret(v);
}

const mask = (value: string): string => (keepValue(value) ? value : MASK);

/** Parameter / variable / flag names whose value is a credential. */
const SECRET_NAME = /(?:token|secret|passw|pwd|signature|credential|api[_-]?key|apikey|private[_-]?key|session|jwt|bearer|cookie)|^(?:key|sig|code|auth|pass|pat|x-amz-credential)$/i;
/** Env-style names: `GITHUB_PERSONAL_ACCESS_TOKEN`, `OPENAI_API_KEY`, `DB_PASSWORD`. */
const SECRET_VAR = /^[A-Za-z_][A-Za-z0-9_]*$/;
const secretVar = (name: string): boolean => SECRET_VAR.test(name) && (SECRET_NAME.test(name) || /(?:^|_)(?:KEY|PAT|AUTH|PASS)(?:_|$)/i.test(name));

/** Whether a config key or variable name holds a credential (`api_key`, `GITHUB_TOKEN`, `model.password`). */
export function isSecretName(name: string): boolean {
  const leaf = name.split('.').pop() ?? name;
  return SECRET_NAME.test(leaf) || secretVar(leaf);
}


/** Hosts whose URL path itself is the credential. */
function maskSecretPath(host: string, path: string): string {
  const h = host.toLowerCase();
  if (/(^|\.)hooks\.slack\.com$/.test(h)) return path.replace(/^(\/services\/)[^?#]+/, `$1${MASK}`);
  if (/(^|\.)(discord|discordapp)\.com$/.test(h)) return path.replace(/^(\/api\/webhooks\/[^/]+\/)[^/?#]+/, `$1${MASK}`);
  if (/(^|\.)telegram\.org$/.test(h)) return path.replace(/^(\/(?:file\/)?bot\d+:)[^/?#]+/, `$1${MASK}`);
  return path;
}

/** `name=value` pairs in a query string or fragment. */
function maskParams(part: string): string {
  return part.replace(/([?#&;])([^=&#;?\s]+)=([^&#;\s]*)/g, (m, sep: string, name: string, value: string) => {
    let n = name;
    try { n = decodeURIComponent(name); } catch { /* keep raw */ }
    return SECRET_NAME.test(n) && value ? `${sep}${name}=${mask(value)}` : m;
  });
}

/** One URL: userinfo password (may contain `@` or `'`), credential paths, secret parameters. */
function maskUrl(url: string): string {
  const m = /^([a-z][a-z0-9+.-]*:\/\/)([^/?#]*)(.*)$/is.exec(url);
  if (!m) return url;
  const [, scheme, authority, rest] = m;
  let auth = authority;
  const at = authority.lastIndexOf('@');
  let host = authority;
  if (at >= 0) {
    const userinfo = authority.slice(0, at);
    host = authority.slice(at + 1);
    const colon = userinfo.indexOf(':');
    if (colon >= 0) {
      const pw = userinfo.slice(colon + 1);
      auth = `${userinfo.slice(0, colon)}:${pw ? mask(pw) : pw}@${host}`;
    } else if (/^[A-Za-z0-9_\-.~%]{16,}$/.test(userinfo)) {
      auth = `${mask(userinfo)}@${host}`; // a token used as the whole userinfo
    }
  }
  const hostname = host.replace(/:\d+$/, '');
  const q = rest.search(/[?#]/);
  const path = q < 0 ? rest : rest.slice(0, q);
  const tail = q < 0 ? '' : rest.slice(q);
  return `${scheme}${auth}${maskSecretPath(hostname, path)}${maskParams(tail)}`;
}

/**
 * Punctuation that ends the sentence or the quoting around a URL, not the URL:
 * a closing bracket only when it has no opening one inside (`${VAR}` keeps
 * its brace), a quote only when the URL has no opening one.
 */
function trimUrlTail(url: string): string {
  const pairs: Record<string, string> = { ')': '(', ']': '[', '}': '{' };
  let end = url.length;
  while (end > 0) {
    const c = url[end - 1];
    const body = url.slice(0, end - 1);
    if (c === '.' || c === ',') { end--; continue; }
    if (c === "'" && !body.includes("'")) { end--; continue; }
    if (c in pairs && body.split(pairs[c]).length - 1 < body.split(c).length) { end--; continue; }
    break;
  }
  return url.slice(0, end);
}

/** URLs in free text end at whitespace, a double quote or `<>`. */
// The scheme is bounded: an unbounded `[a-z0-9+.-]*` rescanned the rest of a
// long `a-a-a…` token from every word boundary (quadratic)
const URL_IN_TEXT = /\b[a-z][a-z0-9+.-]{0,31}:\/\/[^\s"<>]+/gi;
/** `Authorization: Bearer x`, `X-Api-Key: x`, `Cookie: x` header lines. */
const SECRET_HEADER = /(^|[\s"'=])((?:proxy-)?authorization|cookie|x-[\w-]*(?:key|token|secret|auth|session)[\w-]*|api[_-]?key)(\s*:\s*)((?:bearer|basic|token|bot|digest)\s+)?([^\s"',;]+)/gi;
/** `NAME=value` where NAME looks like a credential (env lines, `docker -e`, `env K=V cmd`, inline `sh -c`). */
const SECRET_ASSIGN = /(^|[\s"'`(;&|:$])([A-Za-z_][A-Za-z0-9_]*)\s*=\s*("[^"]*"|'[^']*'|[^\s"'`;&|)]+)/g;
/** `--token=x`, `--token x`, `--api-key x`, `--key=x`, `--pat=x`, `--password x`. */
const SECRET_FLAG = /(^|[\s"'[,])(--?(?:[a-z][\w-]*?[-_])?(?:access[_-]?token|auth[_-]?token|token|api[_-]?key|apikey|key|pat|secret|client[_-]?secret|password|passwd|pass|pwd|credentials?)|-p)(=|\s+|["']\s*,\s*["'])([^\s"'<>,]+)/gi;
/** `-u user:pass` / `--user user:pass` (curl, wget). */
const USER_PASS_FLAG = /(^|[\s"'[,])(-u|--user|--proxy-user)(=|\s+|["']\s*,\s*["'])([^\s:"',]+):([^\s"',]+)/g;

/** A `-p` value that is a port or port mapping, not a password. */
const PORT_LIKE = /^\d+(?::\d+)*(?:\/(?:tcp|udp))?$|^[\d.]+:\d+(?::\d+)?$/;

/**
 * Credentials that ride along inside text a finding quotes — an MCP server
 * URL with a password, `?access_token=` or `#access_token=`, a webhook URL,
 * an `Authorization:` header, `NAME=value` env assignments, `--token` style
 * arguments, `curl -u user:pass` — masked so reports and baselines don't
 * carry them. Only the secret part is replaced; hosts, paths, parameter and
 * variable names stay readable, as do references (`${VAR}`) and placeholders.
 */
export function maskCredentialsInText(text: string): string {
  if (!/[:=@-]/.test(text)) return text;
  return text
    .replace(URL_IN_TEXT, (url) => {
      const body = trimUrlTail(url);
      return maskUrl(body) + url.slice(body.length);
    })
    .replace(SECRET_HEADER, (m, pre: string, name: string, sep: string, scheme: string | undefined, value: string) =>
      (keepValue(value) ? m : `${pre}${name}${sep}${scheme ?? ''}${MASK}`))
    .replace(SECRET_ASSIGN, (m, pre: string, name: string, value: string) =>
      (secretVar(name) && !keepValue(value) ? `${pre}${name}=${MASK}` : m))
    .replace(USER_PASS_FLAG, (m, pre: string, flag: string, sep: string, user: string, pw: string) =>
      (keepValue(pw) ? m : `${pre}${flag}${sep}${user}:${MASK}`))
    .replace(SECRET_FLAG, (m, pre: string, flag: string, sep: string, value: string) => {
      if (value === MASK || keepValue(value) || value.startsWith('-')) return m;
      if (flag === '-p' && PORT_LIKE.test(value)) return m;
      return `${pre}${flag}${sep}${MASK}`;
    });
}

/** `name: value`, `"name": "value"`, `name = value` with a credential name (YAML, JSON, TOML lines). */
const SECRET_KEY_VALUE = /(^|[\s"'{,])(["']?)([A-Za-z_][\w.-]{0,127})\2(\s*[:=]\s*)("[^"]*"|'[^']*'|[^\s,#}]+)/g;

/**
 * One line of a config or source file quoted in a finding (a declarative
 * rule's match): credentials written as `key: value` / `"key": "value"` /
 * `key = value` under a credential name are masked, then everything
 * maskCredentialsInText masks.
 */
export function maskCredentialsInLine(line: string): string {
  const masked = line.replace(SECRET_KEY_VALUE, (m, pre: string, q: string, name: string, sep: string, value: string) => {
    if (!isSecretName(name) || keepValue(value)) return m;
    const quote = /^["']/.test(value) ? value[0] : '';
    return `${pre}${q}${name}${q}${sep}${quote}${MASK}${quote}`;
  });
  return maskCredentialsInText(masked);
}

/**
 * A config value quoted in a finding: a string under a credential name is
 * masked (references and placeholders stay), and every string inside it is
 * masked as text.
 */
export function maskConfigValue(name: string, value: unknown): unknown {
  if (typeof value === 'string') return isSecretName(name) ? mask(value) : maskCredentialsInText(value);
  if (Array.isArray(value)) return value.map(v => maskConfigValue(name, v));
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, maskConfigValue(k, v)]));
  }
  return value;
}

/** Flags whose value is the next argv element. */
const VALUE_FLAG = /^--?(?:[a-z][\w-]*?[-_])?(?:access[_-]?token|auth[_-]?token|token|api[_-]?key|apikey|key|pat|secret|client[_-]?secret|password|passwd|pass|pwd|credentials?)$|^-p$/i;

/**
 * An argv array: each element masked as text, and the element after a
 * credential flag (`--token`, `-p`, `--password`, `-u`) masked as its value —
 * as separate argv elements they never meet in one string.
 */
function maskArgv(args: string[]): string[] {
  const out = args.map(a => maskCredentialsInText(a));
  for (let i = 0; i + 1 < out.length; i++) {
    const flag = args[i];
    const next = out[i + 1];
    if (VALUE_FLAG.test(flag) && !next.startsWith('-') && !keepValue(next) && !(flag === '-p' && PORT_LIKE.test(next))) {
      out[i + 1] = MASK;
    } else if (/^(?:-u|--user|--proxy-user)$/.test(flag)) {
      out[i + 1] = next.replace(/^([^:]+):(.+)$/, (m, user: string, pw: string) => (keepValue(pw) ? m : `${user}:${MASK}`));
    } else if (/^(?:-e|--env)$/.test(flag)) {
      out[i + 1] = next.replace(/^([A-Za-z_][A-Za-z0-9_]*)=(.+)$/, (m, name: string, v: string) => (secretVar(name) && !keepValue(v) ? `${name}=${MASK}` : m));
    }
  }
  return out;
}

const isStringArray = (v: unknown): v is string[] => Array.isArray(v) && v.length > 0 && v.every(x => typeof x === 'string');

/**
 * A copy of a scan result (or any report value) with credentials masked in
 * every string; parsed config files are passed through untouched (reporters
 * never print them); env/header maps have their values masked.
 */
export function maskCredentialsDeep<T>(value: T, key = ''): T {
  if (typeof value === 'string') return maskCredentialsInText(value) as T;
  if (isStringArray(value)) return maskArgv(value) as T;
  if (Array.isArray(value)) return value.map(v => maskCredentialsDeep(v)) as T;
  if (value && typeof value === 'object') {
    if (MASKED_MAPS.has(key)) return maskMap(value as Record<string, unknown>) as T;
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) out[k] = k === 'configFiles' ? v : maskCredentialsDeep(v, k);
    return out as T;
  }
  return value;
}

function maskMap(map: Record<string, unknown>): Record<string, unknown> {
  return Object.fromEntries(Object.entries(map).map(([k, v]) => [k, typeof v === 'string' && !keepValue(v) ? maskValue(v) : v]));
}

export function reportReplacer(this: unknown, key: string, value: unknown): unknown {
  if (typeof value === 'string') return maskCredentialsInText(value);
  if (isStringArray(value)) return maskArgv(value);
  if (key === 'configFiles' && Array.isArray(value)) {
    return value.map(c => (c && typeof c === 'object'
      ? { filePath: (c as { filePath?: unknown }).filePath, format: (c as { format?: unknown }).format }
      : c));
  }
  if (MASKED_MAPS.has(key) && value && typeof value === 'object' && !Array.isArray(value)) {
    return maskMap(value as Record<string, unknown>);
  }
  return value;
}

/** Pretty-printed JSON with config contents stripped and MCP secrets masked. */
export function toReportJson(value: unknown): string {
  return JSON.stringify(value, reportReplacer, 2);
}
