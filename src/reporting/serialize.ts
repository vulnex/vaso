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

import { API_KEY_PATTERNS, isPlaceholderSecret } from '../core/patterns.js';
import { maskUrlSecrets } from '../mcp/config-secrets.js';

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
  // a switch (`websocketRequiresToken: true`), not a credential
  if (/^(?:true|false|null)$/.test(v)) return true;
  // a file holding the credential (`--ssh-key ~/.ssh/id_rsa`), not the credential
  if (/^(?:~|\.{1,2})?\//.test(v)) return true;
  if (/^\$\{[^}]+\}$|^\$[A-Za-z_][A-Za-z0-9_]*$|^\$?\{(?:env|file):[^}]+\}$|^%[A-Za-z_][A-Za-z0-9_]*%$/.test(v)) return true;
  return isPlaceholderSecret(v);
}

const mask = (value: string): string => (keepValue(value) ? value : MASK);

/** Parameter / variable / flag names whose value is a credential. */
const SECRET_NAME = /(?:token|secret|passw|passphrase|pwd|signature|credential|api[_-]?key|apikey|(?:private|client|access|encryption|signing|master)[_-]?key|session|jwt|bearer|cookie)|^(?:key|sig|code|auth|pass|pat|x-amz-credential)$/i;
/**
 * Names that contain a credential word but hold a setting about it: a token
 * budget (`max_tokens`, `tokens_per_minute`, `tokenizer`), a password or
 * session policy, a timeout or limit.
 */
const SETTING_NAME = /^(?:max|min)[_-]?(?:output[_-]?|input[_-]?)?tokens|tokens?[_-]?(?:per|limit|count|budget)|tokeniz|window[_-]?tokens|ttl|(?:policy|timeout|lifetime|limit|count|length|expiry|expiration)$/i;
/** Env-style names: `GITHUB_PERSONAL_ACCESS_TOKEN`, `OPENAI_API_KEY`, `DB_PASSWORD`. */
const SECRET_VAR = /^[A-Za-z_][A-Za-z0-9_]*$/;
// `code` is an OAuth parameter (`?code=`, masked in URLs), not a variable name that holds a secret (`code = notify(msg)`, `CODE=200`)
const secretVar = (name: string): boolean => SECRET_VAR.test(name) && !/^code$/i.test(name) && (SECRET_NAME.test(name) || /(?:^|_)(?:KEY|PAT|AUTH|PASS)(?:_|$)/i.test(name));

/** Whether a config key or variable name holds a credential (`api_key`, `GITHUB_TOKEN`, `model.password`). */
export function isSecretName(name: string): boolean {
  const leaf = name.split('.').pop() ?? name;
  if (SETTING_NAME.test(leaf)) return false;
  return SECRET_NAME.test(leaf) || secretVar(leaf);
}

/**
 * Well-known token formats (`ghp_…`, `sk-proj-…`, `xoxb-…`, `AKIA…`) wherever
 * they stand — a bare argv element or value has no name to go by. Patterns
 * that only match a `NAME=value` assignment are left to SECRET_ASSIGN.
 */
// Each match runs on over the token's remaining characters: a pattern that
// stops early (a fixed-length or first-segments match) must not leave the
// secret's tail readable
// Token formats reports mask but checks don't detect (no Go mirror): GitHub
// fine-grained PATs and app/user/refresh tokens, NVIDIA, Google and AWS STS keys
const MASK_ONLY_TOKENS = [
  /github_pat_[A-Za-z0-9_]{20,}/,
  /gh[usr]_[A-Za-z0-9]{36,}/,
  /\bnvapi-[A-Za-z0-9_-]{20,}/,
  /AIza[0-9A-Za-z_-]{30,}/,
  /ASIA[0-9A-Z]{16,}/,
];
const BARE_TOKEN = new RegExp(
  `(?:${[...API_KEY_PATTERNS.filter(p => !/assignment/i.test(p.name)).map(p => p.pattern), ...MASK_ONLY_TOKENS].map(p => `(?:${p.source})`).join('|')})[A-Za-z0-9_-]*`,
  'g',
);
/** A JWT (`eyJ….eyJ….sig`) under any name: its header and payload are base64 JSON. */
const JWT = /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*/g;
/** A private key's body written into a string (`\n` escapes) or onto the same line. */
const PEM_BODY = /-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----(?:\\[nrt]|[A-Za-z0-9+/=\s])+/g;
/** Cheap pre-check: text with none of these can't hold a bare token. */
const BARE_TOKEN_HINT = /sk-|AKIA|ASIA|gh[pousr]_|github_pat_|glpat-|xox[bp]-|-----BEGIN|\d{10}:|devin-|cog_|apk_|nvapi-|AIza/;

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
  // Bracket and quote counts of url[0, end), kept as the tail is trimmed:
  // recounting the rest of the URL per trimmed character was quadratic
  // (50 KB of `)`: 27 s)
  const count: Record<string, number> = { '(': 0, ')': 0, '[': 0, ']': 0, '{': 0, '}': 0, "'": 0 };
  for (const ch of url) if (ch in count) count[ch]++;
  let end = url.length;
  while (end > 0) {
    const c = url[end - 1];
    if (c === '.' || c === ',') { end--; continue; }
    // c itself is in the count; the text before it isn't
    if ((c === "'" && count["'"] === 1) || (c in pairs && count[pairs[c]] < count[c])) {
      count[c]--;
      end--;
      continue;
    }
    break;
  }
  return url.slice(0, end);
}

/** URLs in free text end at whitespace, a double quote or `<>`. */
// The scheme is bounded: an unbounded `[a-z0-9+.-]*` rescanned the rest of a
// long `a-a-a…` token from every word boundary (quadratic)
const URL_IN_TEXT = /\b[a-z][a-z0-9+.-]{0,31}:\/\/[^\s"<>]+/gi;
/** `Authorization: Bearer x`, `X-Api-Key: x`, `Cookie: x` header lines. */
// The keyword is found by a lookahead: `[\w-]*` on both sides of it
// backtracked over every split of a long `x-keykey…` run (quadratic)
// The name may be quoted and followed by `=`: JSON `"Authorization": "Bearer x"`,
// TOML `"Authorization" = "Bearer x"`
const SECRET_HEADER = /(^|[\s"'=])((?:proxy-)?authorization|cookie|x-(?=[\w-]*?(?:key|token|secret|auth|session))[\w-]*|api[_-]?key)((?:["']\s*[:=]|\s*:)\s*["']?)((?:bearer|basic|token|bot|digest)\s+)?([^\s"',;]+)/gi;
/** `NAME=value` where NAME looks like a credential (env lines, `docker -e`, `env K=V cmd`, inline `sh -c`). */
const SECRET_ASSIGN = /(^|[\s"'`(;&|:$])([A-Za-z_][A-Za-z0-9_]*)(\s*=(?!=)\s*)("[^"]*"|'[^']*'|[^\s"'`;&|)]+)/g;

/**
 * An assignment's unquoted value that is code, not a secret, in source
 * written `name = value` (an env line, `TOKEN=x`, has no spaces): a call or
 * an index (`code = notify(msg)`, `token = headers["x"]`), a member reference
 * (`password = args.password`) or a literal keyword. A bare word is kept
 * masked (`password = hunter2` in an INI file), and so is a dotted value
 * with digits inside its segments (a JWT is `eyJ….eyJ….sig`).
 */
function codeValue(value: string, sep: string): boolean {
  if (!/\s/.test(sep) || /^["']/.test(value)) return false;
  if (/^[A-Za-z_$][\w$.]*\s*[([]/.test(value)) return true;
  if (/^(?:None|null|undefined|true|false|True|False|nil)$/.test(value)) return true;
  const parts = value.split('.');
  return parts.length > 1 && parts.every((p) => /^[A-Za-z_$][A-Za-z_$]{0,23}\d{0,2}$/.test(p));
}

/** `--token=x`, `--token x`, `--api-key x`, `--key=x`, `--pat=x`, `--password x`. */
const SECRET_FLAG = /(^|[\s"'[,])(--?(?:[a-z][\w-]*?[-_])?(?:access[_-]?token|auth[_-]?token|token|api[_-]?key|apikey|key|pat|secret|client[_-]?secret|password|passwd|pass|pwd|credentials?|auth|bearer)|-p)(=|\s+|["']\s*,\s*["'])([^\s"'<>,]+)/gi;
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
  if (!/[:=@-]/.test(text) && !BARE_TOKEN_HINT.test(text)) return text;
  const pem = text.includes('-----BEGIN') ? text.replace(PEM_BODY, MASK) : text;
  const jwt = pem.includes('eyJ') ? pem.replace(JWT, MASK) : pem;
  const bare = BARE_TOKEN_HINT.test(jwt) ? jwt.replace(BARE_TOKEN, (m) => (keepValue(m) ? m : MASK)) : jwt;
  return bare
    .replace(URL_IN_TEXT, (url) => {
      const body = trimUrlTail(url);
      // plus what MCP-003 reads as a credential: secret paths (Zapier MCP), random path tokens
      return maskUrl(maskUrlSecrets(body)) + url.slice(body.length);
    })
    .replace(SECRET_HEADER, (m, pre: string, name: string, sep: string, scheme: string | undefined, value: string) =>
      (keepValue(value) ? m : `${pre}${name}${sep}${scheme ?? ''}${MASK}`))
    .replace(SECRET_ASSIGN, (m, pre: string, name: string, sep: string, value: string) =>
      (secretVar(name) && !keepValue(value) && !codeValue(value, sep) ? `${pre}${name}=${MASK}` : m))
    .replace(USER_PASS_FLAG, (m, pre: string, flag: string, sep: string, user: string, pw: string) =>
      (keepValue(pw) ? m : `${pre}${flag}${sep}${user}:${MASK}`))
    .replace(SECRET_FLAG, (m, pre: string, flag: string, sep: string, value: string) => {
      if (value === MASK || keepValue(value) || value.startsWith('-')) return m;
      if (flag === '-p' && PORT_LIKE.test(value)) return m;
      return `${pre}${flag}${sep}${MASK}`;
    });
}

/**
 * `name: value`, `"name": "value"`, `name = value` with a credential name
 * (YAML, JSON, TOML lines). A value that opens an object or array is not the
 * name's value: the scan moves on to the pairs inside it
 * (`{"providers":{"custom":{"apiKey":"x"}}}`). YAML anchors and tags before
 * the value (`token: &tok x`, `token: !!str x`) are part of the separator;
 * quoted strings honour escaped quotes; TOML `"""…"""` / `'''…'''` are one string.
 */
/** `\"name\":\"value\"` at any escaping depth: groups 1, 3 and 5 are the quote runs. */
const ESCAPED_JSON_PAIR = /(\\+["'])([A-Za-z_][\w.-]{0,63})(\\+["']\s*:\s*\\+["'])([^"'\\\s]{4,})(\\+["'])/g;
const SECRET_KEY_VALUE = /(^|[\s"'{,])(["']?)([A-Za-z_][\w.-]{0,127})\2(\s*[:=]\s*(?:[&!][^\s,{}[\]]*\s+)*)("{3}[\s\S]*?"{3}|'{3}[\s\S]*?'{3}|"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|\$\{[^}\s]*\}|(?![{[])[^\s,#}\]]+)/g;
/**
 * A line that is nothing but a base64 run the length of a PEM body line (a
 * YAML block scalar holding a private key puts each on its own line).
 */
const BASE64_LINE = /^(\s*)([A-Za-z0-9+/]{40,76}={0,2})(\s*)$/;
/** `tokens: [a, b]`, `"keys": ["a", "b"]`: a flow list of scalars under a credential name. */
const SECRET_KEY_LIST = /(^|[\s"'{,])(["']?)([A-Za-z_][\w.-]{0,127})\2(\s*[:=]\s*)\[((?:[^[\]{}\n$]|\$\{[^}\n]*\}|\$)*)\]/g;
/**
 * A whole YAML / INI line `name: value` or `name = value` whose unquoted value
 * runs to the end of the line or a ` #` comment: `password: correct horse
 * battery`, `token: abc#def` (no space before `#`: not a comment).
 */
const SECRET_LINE_VALUE = /^(\s*(?:-\s+)?)([A-Za-z_][\w.-]{0,127})(\s*[:=]\s*(?:[&!][^\s,{}[\]]*\s+)*)([^\s"'{[&!#|>][^\n]*)$/;

/**
 * One line of a config or source file quoted in a finding (a declarative
 * rule's match): credentials written as `key: value` / `"key": "value"` /
 * `key = value` under a credential name are masked, then everything
 * maskCredentialsInText masks.
 */
export function maskCredentialsInLine(raw: string): string {
  // JSON escaped inside a string or a shell argument (`{\"apiKey\":\"…\"}`)
  const line = raw.includes('\\') ? raw.replace(ESCAPED_JSON_PAIR, (m, q1: string, name: string, q2: string, value: string, q3: string) =>
    (isSecretName(name) && !keepValue(value) ? `${q1}${name}${q2}${MASK}${q3}` : m)) : raw;
  const b64 = BASE64_LINE.exec(line);
  if (b64 && /[A-Z]/.test(b64[2]) && /[a-z]/.test(b64[2]) && /\d/.test(b64[2])) return `${b64[1]}${MASK}${b64[3]}`;
  const whole = line.replace(SECRET_LINE_VALUE, (m, pre: string, name: string, sep: string, rest: string) => {
    // a ` #` comment ends the value (found by search: a lazy value before an
    // optional comment group rescans the line per character)
    const hash = rest.search(/\s#/);
    const value = (hash < 0 ? rest : rest.slice(0, hash)).trimEnd();
    if (!isSecretName(name) || keepValue(value) || (sep.includes('=') && codeValue(value, sep))) return m;
    return `${pre}${name}${sep}${MASK}${rest.slice(value.length)}`;
  });
  const listed = whole.replace(SECRET_KEY_LIST, (m, pre: string, q: string, name: string, sep: string, items: string) =>
    (isSecretName(name)
      ? `${pre}${q}${name}${q}${sep}[${items.replace(/[^,\s"']+(?:\s+[^,\s"']+)*/g, (v) => (keepValue(v) ? v : MASK))}]`
      : m));
  const masked = listed.replace(SECRET_KEY_VALUE, (m, pre: string, q: string, name: string, sep: string, value: string) => {
    // `name = call(…)` in a source line is code (YAML `name: …` is always a value)
    if (!isSecretName(name) || keepValue(value) || (sep.includes('=') && codeValue(value, sep))) return m;
    const quote = /^["']/.test(value) ? value[0] : '';
    return `${pre}${q}${name}${q}${sep}${quote}${MASK}${quote}`;
  });
  return maskCredentialsInText(masked).replace(CUT_TOKEN_TAIL, (m, prefix: string, cut: string) => `${prefix}${MASK}${cut}`);
}

/**
 * A token a check's snippet cut off (`…slice(0, 120)`, ` ...`, `…`): too short
 * to match its pattern any more, so BARE_TOKEN leaves it — its prefix ends the
 * snippet's last word.
 */
const CUT_TOKEN_TAIL = /\b(sk-|AKIA|ASIA|gh[pousr]_|github_pat_|glpat-|xox[abprs]-|devin-|cog_|apk_|nvapi-|AIza)[A-Za-z0-9_.$-]{4,}((?: ?\.\.\.|…)?)$/;

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
const VALUE_FLAG = /^--?(?:[a-z][\w-]*?[-_])?(?:access[_-]?token|auth[_-]?token|token|api[_-]?key|apikey|key|pat|secret|client[_-]?secret|password|passwd|pass|pwd|credentials?|auth|bearer)$|^-p$/i;

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

/**
 * An evidence snippet quotes a line of a config or source file, where a
 * credential is written `"key": "value"` / `key: value` as often as
 * `KEY=value` — a one-line JSON file puts every key a check didn't match on
 * the same line as the one it did.
 */
function maskString(value: string, key: string): string {
  return key === 'snippet' ? maskCredentialsInLine(value) : maskCredentialsInText(value);
}

const isStringArray = (v: unknown): v is string[] => Array.isArray(v) && v.length > 0 && v.every(x => typeof x === 'string');

/**
 * A copy of a scan result (or any report value) with credentials masked in
 * every string; parsed config files are passed through untouched (reporters
 * never print them); env/header maps have their values masked.
 */
export function maskCredentialsDeep<T>(value: T, key = ''): T {
  if (typeof value === 'string') return maskString(value, key) as T;
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
  if (typeof value === 'string') return maskString(value, key);
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
