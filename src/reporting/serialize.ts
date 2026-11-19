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

import { API_KEY_PATTERNS, MAX_SNIPPET, OAUTH_TOKEN_VALUE_PATTERNS, isEnvReference, isPathValue, isPlaceholderSecret, truncateSnippet } from '../core/patterns.js';
import { maskCommandCredentials, maskUrlSecrets } from '../mcp/config-secrets.js';
import { escapeJsonUnsafe } from './text-safety.js';
import { EXTRA_TOKEN_PATTERNS } from '../analyzers/secret-values.js';
import {
  PASSWORD_P_CLIENT_IN_TEXT, REDIS_CLI_IN_TEXT, SEPARATE_P_CLIENT_IN_TEXT, isFlagShaped, isKeyAfterK, isPasswordAfterA, isPasswordAfterP,
  isPasswordClient, isRedisCli, isSeparatePasswordClient, clientAndStdinHits,
} from '../mcp/argv-rules.js';

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
  // quotes may be backslash-escaped (`KEY=\"value\"` inside a JSON string)
  const v = value.trim().replace(/^\\*['"]|\\*['"]$/g, '');
  if (v === '' || v === MASK) return true;
  // a switch (`websocketRequiresToken: true`), not a credential
  if (/^(?:true|false|null)$/.test(v)) return true;
  // a file holding the credential (`--ssh-key ~/.ssh/id_rsa`), not the
  // credential — judged by shape: a base64 secret starts with `/` 1 time in 64
  if (isPathValue(v)) return true;
  // `${VAR}`, `$VAR`, `{env:VAR}`, `%VAR%` — but `$uperS3cret…` is a password
  // that starts with `$`, and `${VAR:-<secret>}` stores the secret anyway
  if (/^[$%{]/.test(v) && isEnvReference(v)) return true;
  if (/^\$\{[^}]+\}$/.test(v) && !/[:=]/.test(v)) return true;
  if (!isPlaceholderSecret(v)) return false;
  // A placeholder word inside a passphrase (`correct your horse …`) doesn't
  // make it a docs example: a phrase is one only when every word is filler
  // (`insert your api key here`) — `...`, `<…>`, `xxxx` still mark it
  if (/\s/.test(v) && !STRONG_PLACEHOLDER.test(v)) {
    return v.split(/\s+/).every(w => FILLER_WORD.test(w.replace(/^[^A-Za-z0-9]+|[^A-Za-z0-9]+$/g, '')));
  }
  return true;
}

const STRONG_PLACEHOLDER = /\.{3}|\u2026|x{4,}|X{4,}|\*{3,}|^<[^>]*>$|^\{\{[^}]*\}\}$|EXAMPLE/;
/** Words a placeholder phrase is made of. */
const FILLER_WORD = /^(?:|your|my|the|a|an|own|here|goes|put|enter|insert|replace|with|this|that|example|sample|dummy|placeholder|changeme|change|me|fake|redacted|real|actual|api|key|token|secret|password|passphrase|pass|value|string|of|to|for|it)$/i;

const mask = (value: string): string => (keepValue(value) ? value : MASK);

/** Parameter / variable / flag names whose value is a credential. */
// `…Key` names: camelCase (`appKey`, `hmacKey`), dashed headers
// (`Ocp-Apim-Subscription-Key`) and connection-string keys (`AccountKey=`)
const SECRET_NAME = /(?:token|secret|passw|passphrase|pwd|signature|credential|api[_-]?key|apikey|(?:private|priv|client|access|encryption|signing|master|app|deploy|write|licen[cs]e|hmac|auth|service|webhook|account|subscription|admin|ingest|sdk|sas)[_-]?key|session|jwt|bearer|cookie)|^(?:key|sig|code|auth|pass|pat|pin|pk|creds?|x-amz-credential)$|[_-]creds?$/i;
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
/** An assigned name that holds a credential, not a setting about one (`ssh_session_ttl_secs`, `max_tokens`). */
const secretAssignName = (name: string): boolean => secretVar(name) && !SETTING_NAME.test(name);

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
// Token formats reports mask but no check detects (no Go mirror): Stripe,
// SendGrid, npm, PyPI, DigitalOcean, Shopify, Linear, Figma, Square, Twilio,
// Mailgun, Docker Hub and Perplexity keys, and a 32-byte `0x` hex key (an
// Ethereum private key, or a hash — public, and harmless to hide)
const MASK_ONLY_TOKENS = [
  /\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}/,
  /\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}/,
  /\bnpm_[A-Za-z0-9]{36,}/,
  /\bpypi-[A-Za-z0-9_-]{50,}/,
  /\bdop_v1_[a-f0-9]{64}/,
  /\bshp(?:at|ss|ca|pa)_[a-fA-F0-9]{32,}/,
  /\blin_api_[A-Za-z0-9]{40,}/,
  /\bfigd_[A-Za-z0-9_-]{30,}/,
  /\bsq0(?:atp|csp)-[A-Za-z0-9_-]{22,}/,
  /\bSK[0-9a-f]{32}\b/,
  /\bkey-[0-9a-f]{32}\b/,
  /\bdckr_pat_[A-Za-z0-9_-]{20,}/,
  /\bpplx-[A-Za-z0-9]{40,}/,
  /\b0x[0-9a-fA-F]{64}\b/,
];
/**
 * Every token format VASO knows: what the checks detect (`API_KEY_PATTERNS`,
 * `EXTRA_TOKEN_PATTERNS`, OAuth access tokens) plus the mask-only formats —
 * derived from the shared lists, so a format a check reports is never
 * printed by a report. Anchors are dropped (the lists judge whole values);
 * a token glued to a word (`task-…`) is not one.
 */
const TOKEN_FORMATS = [
  ...API_KEY_PATTERNS.filter(p => !/assignment/i.test(p.name)).map(p => p.pattern),
  ...EXTRA_TOKEN_PATTERNS,
  ...OAUTH_TOKEN_VALUE_PATTERNS.filter(p => !/JWT/.test(p.name)).map(p => p.pattern),
  ...MASK_ONLY_TOKENS,
];
const unanchored = (re: RegExp): string => re.source.replace(/^\^/, '').replace(/\$$/, '');
function tokenRegex(formats: RegExp[], flags: string): RegExp {
  return new RegExp(`(?<![A-Za-z0-9])(?:${formats.map(p => `(?:${unanchored(p)})`).join('|')})[A-Za-z0-9_-]*`, flags);
}
// a format judged case-insensitively (`sk-lf-<UUID>`) keeps its flag
const BARE_TOKEN = tokenRegex(TOKEN_FORMATS.filter(p => !p.flags.includes('i')), 'g');
const BARE_TOKEN_I = tokenRegex(TOKEN_FORMATS.filter(p => p.flags.includes('i')), 'gi');

/**
 * The literal start of a token format, as regex source (`ghp_`, `gh[ousr]_`,
 * `sk-ant-`): characters and letter-only classes up to the first other
 * construct. Undefined when it has fewer than two literal characters.
 */
function literalHead(re: RegExp): string | undefined {
  const src = unanchored(re).replace(/^\\b/, '');
  let head = '';
  let literals = 0;
  for (let i = 0; i < src.length;) {
    const c = src[i];
    if (/[A-Za-z0-9_ ]/.test(c) || (c === '-' && i > 0)) { head += c; literals++; i++; continue; }
    if (c === '\\' && /[-._]/.test(src[i + 1] ?? '')) { head += src.slice(i, i + 2); literals++; i += 2; continue; }
    const cls = /^\[[a-z]+\]/i.exec(src.slice(i));
    // a class followed by a quantifier is a run, not one letter of a prefix
    if (cls && !/^[{*+?]/.test(src[i + cls[0].length] ?? '')) { head += cls[0]; i += cls[0].length; continue; }
    break;
  }
  return literals >= 2 ? head : undefined;
}
/** Cheap pre-check: text with none of these can't hold a bare token. */
const BARE_TOKEN_HINT = new RegExp(TOKEN_FORMATS.map(p => literalHead(p) ?? unanchored(p)).join('|'), 'i');
/**
 * Prefixes of the formats checks detect, for a token a snippet cut short:
 * the ones a word doesn't start with (ending in a separator, or 4+ characters).
 */
const CUT_PREFIXES = [...new Set(TOKEN_FORMATS.slice(0, TOKEN_FORMATS.length - MASK_ONLY_TOKENS.length)
  .map(literalHead)
  .filter((h): h is string => !!h && !h.startsWith('-') && (/[-_.]$/.test(h) || h.replace(/\[[^\]]*\]/g, 'x').length >= 4)))];
/** A JWT (`eyJ….eyJ….sig`) under any name: its header and payload are base64 JSON. */
const JWT = /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*/g;
/** A private key's body written into a string (`\n` escapes) or onto the same line. */
const PEM_BODY = /-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----(?:\\[nrt]|[A-Za-z0-9+/=\s])+/g;

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
  } else if (!authority.startsWith('[')) {
    // `scheme://user:<pw>` cut before its `@` (a snippet's length limit): a
    // host's port is digits, so anything else after the colon is the password
    const colon = authority.indexOf(':');
    const pw = colon < 0 ? '' : authority.slice(colon + 1);
    if (pw && !/^\d+$/.test(pw) && !keepValue(pw)) {
      auth = `${authority.slice(0, colon)}:${MASK}`;
      host = '';
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
/**
 * A vendor header in HTTP case whose last word names a credential
 * (`Ocp-Apim-Subscription-Key: x`, `X-Goog-Api-Key`, `Private-Token`).
 * Case-sensitive: the capitals tell a header from a YAML key (`cache-key:`).
 */
const SECRET_DASHED_HEADER = /(^|[\s"'=])((?:[A-Z][A-Za-z0-9]*-)+(?:Key|Token|Secret|Signature|Session|Auth))((?:["']\s*[:=]|\s*:)\s*["']?)([^\s"',;]+)/g;
/**
 * `NAME=value` where NAME looks like a credential (env lines, `docker -e`,
 * `env K=V cmd`, inline `sh -c`), also as a flag's value or a dotted path
 * (`--env=K=V`, `--from-literal=password=X`, `--set auth.password=X`).
 */
// (a value may be quoted with escaped quotes: `DB_PASSWORD=\"x\"` inside a JSON string;
// an object or list (`credentials = {"primary":…}`, `tokens = ["***"]`) is not one value —
// its bracket is kept, the values inside are masked where they stand)
const SECRET_ASSIGN = /(^|[\s"'`(;&|:$=.])([A-Za-z_][A-Za-z0-9_]*)(\s*=(?!=)\s*)(\\+"[^"\\\n]*\\+"|"[^"]*"|'[^']*'|(?![{[](?:["'{[\]}\s]|$))[^\s"'`;&|)\\]+)/g;

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

/**
 * A string literal in code: `"…"`, `'…'` or `` `…` ``, escapes honoured. An
 * unclosed `"` or backtick runs to the end of the line (a value cut short, or
 * continued on the next line); an unclosed `'` is an apostrophe.
 */
interface CodeLiteral { start: number; end: number; closed: boolean }

/** The string literals of a line, left to right (a quote escaped outside one is a plain character). */
function codeLiterals(line: string): CodeLiteral[] {
  const out: CodeLiteral[] = [];
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (c !== '"' && c !== "'" && c !== '`') continue;
    if (i > 0 && line[i - 1] === '\\') continue;
    let j = i + 1;
    for (; j < line.length; j++) {
      if (line[j] === '\\') { j++; continue; }
      if (line[j] === c) break;
    }
    if (j < line.length) {
      out.push({ start: i, end: j + 1, closed: true });
      i = j;
    } else if (c !== "'") {
      out.push({ start: i, end: line.length, closed: false });
      break;
    }
  }
  return out;
}

/** `${NAME:-word}`, `${NAME-word}`, `${NAME:=word}`, `${NAME:+word}`: a shell default, assigned or alternate value. */
const SHELL_DEFAULT = /\$\{(#?[A-Za-z_]\w*)(:?[-=+?])([^}]*)\}/g;

function maskShellDefaults(text: string): string {
  if (!text.includes('${')) return text;
  return text.replace(SHELL_DEFAULT, (m, name: string, op: string, word: string) =>
    (word === '' || word === MASK || keepValue(word) ? m : `\${${name}${op}${MASK}}`));
}

/**
 * A literal in a credential's value, masked: kept only when it is a reference
 * or placeholder (keepValue) or names the environment variable a lookup reads
 * (`os.getenv("DB_PASSWORD")`); a shell default inside it (`"${KEY:-pw}"`)
 * is masked on its own.
 */
function maskValueLiteral(line: string, lit: CodeLiteral): string {
  const q = line[lit.start];
  const body = line.slice(lit.start + 1, lit.closed ? lit.end - 1 : lit.end);
  const close = lit.closed ? q : '';
  if (body === '' || body === MASK) return `${q}${body}${close}`;
  if (lit.closed && literalIsName(line, lit)) return `${q}${body}${close}`;
  if (body.includes('${')) {
    const defaults = maskShellDefaults(body);
    // nothing but references around the masked defaults: they stay readable
    if (/^(?:\s*\$\{[^}]*\})+\s*$/.test(defaults) && defaults.replace(/\$\{[^}]*\}/g, '').trim() === '') return `${q}${defaults}${close}`;
    return `${q}${MASK}${close}`;
  }
  return keepValue(body) ? `${q}${body}${close}` : `${q}${MASK}${close}`;
}

/**
 * A prompt shown when asking for a credential (`getpass("Password: ")`), not
 * the credential.
 */
const PROMPT_CALL_BEFORE = /\b(?:getpass(?:\.getpass)?|input|raw_input|prompt|askpass|readline\.question)\s*\(\s*$/;

/**
 * A literal in a credential's value that names something rather than being a
 * value it may take: the variable an environment lookup reads
 * (`os.getenv("DB_PASSWORD")`), an index (`headers["x-token"]`), an object
 * key (`{"value": …}`), a prompt (`getpass("Password: ")`).
 */
function literalIsName(line: string, lit: CodeLiteral): boolean {
  const before = line.slice(Math.max(0, lit.start - 64), lit.start);
  const after = line.slice(lit.end, lit.end + 8);
  if (ENV_LOOKUP_BEFORE.test(before) || PROMPT_CALL_BEFORE.test(before)) return true;
  // `x["key"]` — not a list (`= ["pw"]`): the bracket follows a name, a call or an index
  if (/[\w$)\]]\s*\[\s*$/.test(before) && /^\s*\]/.test(after)) return true;
  // `{"key": …}`, `, 'key' => …` — not a ternary's branch (`? "a" : "b"`)
  return /[{,]\s*$/.test(before) && /^\s*(?::(?!:)|=>)/.test(after);
}

/** Where a credential's value starts on a line: after `name =`, `name:`, `"name":`, `["name"] =`, `name ||=`. */
interface CredentialPosition { at: number; valueStart: number; plain?: boolean; url?: boolean }

/** A name for an address (`TOKEN_URL`, `tokenEndpoint`, `authUri`): its value is a URL, not the credential the name mentions. */
const URL_NAME = /(?:url|uri|endpoint)$/i;
/**
 * A literal that is an address and nothing else: an http(s) URL with no
 * userinfo, query or fragment (where a credential could ride along), or a
 * template that only appends a path to interpolated values
 * (`{AUTH_HOST}/oauth/token`, `${base}/token`).
 */
function plainAddress(body: string): boolean {
  if (/^https?:\/\/[^\s@?#'"`{}$\\]+$/i.test(body)) return true;
  const rest = body.replace(/\$?\{[A-Za-z_][\w.]*\}/g, '');
  return rest !== body && /^(?:https?:\/\/[^\s@?#'"`{}$\\]*|\/[\w\-./~%]*)?$/i.test(rest);
}

/**
 * A bare name and the separator that gives it a value: an assignment
 * (`=`, `:=`, `||=`, `??=`, `&&=`, `+=`), a keyword argument (`password=`),
 * or a key (`password:` in an object, YAML, a Python annotation).
 */
const BARE_POSITION = /(?<![\w$.@\\-])([$@]{0,2}[A-Za-z_][\w$]*(?:-[A-Za-z0-9_$]+)*(?:(?:\.|->|::|\?\.)[A-Za-z_$][\w$]*)*)(\s*(?:\|\|=|\?\?=|&&=|:=|\+=|=(?![=>~])|:(?![:=/])))/g;
/** After a quoted key: `"password": …`, `'password' => …`, `"password" = …` (TOML). */
const QUOTED_KEY_SEP = /^\s*(?::(?!:)|=>|=(?![=>~]))/;
/** After `["password"]`: an assignment to that subscript. */
const SUBSCRIPT_SEP = /^\s*\]\s*(?:\|\|=|\?\?=|&&=|\+=|=(?![=>~]))/;

function credentialPositions(line: string, literals: CodeLiteral[]): CredentialPosition[] {
  const out: CredentialPosition[] = [];
  let from = 0;
  const bare = (segment: string, offset: number) => {
    BARE_POSITION.lastIndex = 0;
    for (let m = BARE_POSITION.exec(segment); m; m = BARE_POSITION.exec(segment)) {
      const leaf = m[1].split(/\.|->|::|\?\./).pop()!.replace(/^[$@]+/, '');
      // `code` names a status or a script far more often than an OAuth code
      if (/^code$/i.test(leaf) || !isSecretName(leaf)) continue;
      // `name = "…"` / `name: "…"`: a plain literal, SECRET_ASSIGN / SECRET_KEY_VALUE's to mask
      out.push({ at: offset + m.index, valueStart: offset + m.index + m[0].length, plain: /^\s*[:=]$/.test(m[2]), ...(URL_NAME.test(leaf) ? { url: true } : {}) });
    }
  };
  for (const lit of literals) {
    bare(line.slice(from, lit.start), from);
    from = lit.end;
    if (!lit.closed) break;
    const body = line.slice(lit.start + 1, lit.end - 1);
    if (body.length > 128 || !isSecretName(body)) continue;
    const after = line.slice(lit.end, lit.end + 16);
    const key = QUOTED_KEY_SEP.exec(after);
    if (key) { out.push({ at: lit.start, valueStart: lit.end + key[0].length }); continue; }
    const sub = SUBSCRIPT_SEP.exec(after);
    if (sub && /\[\s*$/.test(line.slice(Math.max(0, lit.start - 8), lit.start))) out.push({ at: lit.start, valueStart: lit.end + sub[0].length });
  }
  if (from < line.length) bare(line.slice(from), from);
  return out.sort((a, b) => a.at - b.at);
}

/** Text ending a line that leaves an expression open: a line continuation or a binary operator. */
const OPEN_TAIL = /(?:\\|\b(?:or|and|not)|\|\||&&|\?\?|\?:|[?:+|&=,([{-])\s*$/;

/**
 * Where a credential's value expression ends: at a `,` / `;` / closing
 * bracket at its own depth, a ` #` or ` //` comment, or the end of the line.
 * `open` when it runs past the line (brackets left open, a string left
 * unclosed, or an operator / `\` at the end).
 */
function valueExtent(line: string, start: number, literals: CodeLiteral[], li: number): { end: number; open: boolean } {
  let depth = 0;
  let k = li;
  let i = start;
  for (; i < line.length; i++) {
    while (k < literals.length && literals[k].end <= i) k++;
    const lit = literals[k];
    if (lit && lit.start === i) {
      if (!lit.closed) return { end: line.length, open: true };
      i = lit.end - 1;
      continue;
    }
    const c = line[i];
    if (c === '(' || c === '[' || c === '{') depth++;
    else if (c === ')' || c === ']' || c === '}') {
      if (depth === 0) break;
      depth--;
    } else if ((c === ',' || c === ';') && depth === 0) break;
    else if ((c === '#' || (c === '/' && line[i + 1] === '/')) && depth === 0 && /\s/.test(line[i - 1] ?? '')) break;
  }
  const open = i >= line.length && (depth > 0 || OPEN_TAIL.test(line.slice(start)));
  return { end: i, open };
}

/**
 * Every credential-named position on a line — an assignment target
 * (`password = …`, `self.password = …`, `config["password"] = …`,
 * `password ||= …`), a keyword argument, a dict / object / YAML key — with
 * the string literals of its value expression masked: a fallback
 * (`os.getenv("X") or "pw"`), a ternary's branch, a call's default argument
 * (`os.getenv("Y", "pw")`), a shell default (`${DB_PW:-pw}`). A literal is
 * kept only when it is a reference or placeholder, or the variable name an
 * environment lookup reads. `open` is whether the last such value runs on
 * past the end of the line.
 */
function maskCredentialValues(line: string, literalFree = false): { text: string; open: boolean } {
  if (!/[=:]/.test(line) || (!literalFree && !/["'`]|\$\{/.test(line))) return { text: line, open: false };
  const literals = codeLiterals(line);
  const positions = credentialPositions(line, literals);
  if (positions.length === 0) return { text: line, open: false };
  let out = '';
  let last = 0;
  let li = 0;
  let open = false;
  for (const pos of positions) {
    // a position inside a value already masked (`password = {"token": …}`)
    if (pos.at < last) continue;
    while (li < literals.length && literals[li].end <= pos.valueStart) li++;
    const only = literals[li];
    if (pos.plain && only && only.closed && line[only.start] !== '`' && !line.slice(only.start, only.end).includes('${')
      && line.slice(pos.valueStart, only.start).trim() === '' && /^\s*(?:$|[,;)\]}]|#|\/\/)/.test(line.slice(only.end, only.end + 64))) continue;
    const extent = valueExtent(line, pos.valueStart, literals, li);
    // an address under an address name: `TOKEN_URL = f"{AUTH_HOST}/oauth/token"`, `tokenUrl = new URL("http://…")`
    if (pos.url) {
      const lits = literals.slice(li).filter((l) => l.start < extent.end);
      if (lits.length > 0 && lits.every((l) => l.closed && plainAddress(line.slice(l.start + 1, l.end - 1)))) continue;
    }
    let cursor = pos.valueStart;
    out += line.slice(last, cursor);
    for (let k = li; k < literals.length && literals[k].start < extent.end; k++) {
      const lit = literals[k];
      out += maskShellDefaults(line.slice(cursor, lit.start)) + maskValueLiteral(line, lit);
      cursor = lit.end;
    }
    const tailEnd = Math.max(cursor, extent.end);
    out += maskShellDefaults(line.slice(cursor, tailEnd));
    last = tailEnd;
    open = extent.open;
  }
  return { text: out + line.slice(last), open };
}

function maskCodeFallbacks(text: string): string {
  if (!text.includes('\n')) return maskCredentialValues(text).text;
  return text.split('\n').map(l => maskCredentialValues(l).text).join('\n');
}

/** Whether a credential's value on `line` runs on to the next line (`token = os.getenv("X") or \`). */
function credentialValueContinues(line: string): boolean {
  return maskCredentialValues(line, true).open;
}

/**
 * Code in parentheses (`api_key = (os.environ.get("K") or`, a value continued
 * on the next lines): shown, with its string literals masked but an
 * environment variable's name (maskValueText).
 */
function groupedCode(value: string, sep: string): boolean {
  return value.startsWith('(') && codeValue(value.replace(/^\(+\s*/, ''), sep);
}

/** The credential words a flag name ends in, dashed/underscored (`--api-key`) or any case. */
const FLAG_WORD = String.raw`(?:access[_-]?token|auth[_-]?token|token|api[_-]?key|apikey|key|pat|secret|client[_-]?secret|password|passwd|pass|pwd|pw|credentials?|auth|bearer)`;
/** The same words ending a camelCase flag (`--apiToken`, `--oauth2Bearer`, `--secretKey`). */
const CAMEL_FLAG_WORD = String.raw`[a-z][a-z0-9]*(?:[A-Z][a-z0-9]*)*?(?:AccessToken|AuthToken|Token|ApiKey|Key|Pat|Secret|Password|Passwd|Pass|Pwd|Credentials?|Auth|Bearer)`;
/** Flag/value separators: `=`, ` = `, whitespace, and `", "` between JSON argv elements. */
const FLAG_SEP = String.raw`(\s*=\s*|\s+|["']\s*,\s*["'])`;
/** `--token=x`, `--token x`, `--api-key x`, `--key=x`, `--pat=x`, `--password x`. */
// A value may start with `-` unless it is flag-shaped (shared argv rule 1;
// `replaceFlagValues` rescans from a flag-shaped one: `--no-auth --api-key x`).
// Escaped quotes may wrap the value (`--password=\"x\"`).
/** A one-word quoted value (`-p "pw"`, `--password="pw"`, `-p'pw'`): the quotes are the shell's, not the value's. */
const QUOTED_WORD = String.raw`\\*"[^"\\\s,]+\\*"|'[^'\s,]+'`;
const FLAG_VALUE = String.raw`(\\+"[^"\\\n]*\\+"|${QUOTED_WORD}|[^\s"'<>,\\][^\s"'<>,]*)`;
const SECRET_FLAG = new RegExp(String.raw`(^|[\s"'[,])(--?(?:[a-z][\w-]*?[-_])?${FLAG_WORD})${FLAG_SEP}${FLAG_VALUE}`, 'gi');
const CAMEL_SECRET_FLAG = new RegExp(String.raw`(^|[\s"'[,])(--?${CAMEL_FLAG_WORD})${FLAG_SEP}${FLAG_VALUE}`, 'g');
/** `-p <pw>`, `-k <key>`, `redis-cli -a <pw>`: judged by the shared argv rules 2–4. */
const SHORT_FLAG = new RegExp(String.raw`(^|[\s"'[,])(-[pka])(\s+|["']\s*,\s*["'])${FLAG_VALUE}`, 'g');
/** `mysql -pSECRET`, `mysql -p"SECRET"`: a password glued to `-p`. */
const ATTACHED_P = new RegExp(String.raw`(^|[\s"'[,])(-p)()(${QUOTED_WORD}|[^\s"'<>,]+)`, 'g');
/** `-u user:pass` / `--user user:pass` (curl, wget), the pair quoted or not (`-u "user:pass"`). */
const USER_PASS_FLAG = /(^|[\s"'[,])(-u|--user|--proxy-user)((?:=|\s+)\\*["']?|["']\s*,\s*["'])([^\s:"',\\]+):([^\s"',\\]+)/g;
/** Words of the sentence a flag is quoted in (`after --bot-token in server arguments`), not its value. */
const PROSE_WORD = /^(?:in|on|at|to|of|for|from|by|with|and|or|is|was|the|a|an|as|flag|value|argument|arguments)$/;

/** How far back a flag's command is looked for: a whole line sliced per flag was
 *  quadratic (a 400 KB argument of `-p x` repeated took two minutes). */
const COMMAND_LOOKBACK = 512;

/** The command a flag at `offset` belongs to: the text since the last `;`, `&`, `|` or line break, at most COMMAND_LOOKBACK back. */
function commandBefore(text: string, offset: number): string {
  const from = Math.max(0, offset - COMMAND_LOOKBACK);
  const before = text.slice(from, offset);
  return before.slice(Math.max(before.lastIndexOf(';'), before.lastIndexOf('&'), before.lastIndexOf('|'), before.lastIndexOf('\n')) + 1);
}

/**
 * `re` (groups: boundary, flag, separator, value) with each value `judge`
 * accepts masked. A flag-shaped "value" is the next flag: the scan resumes
 * at it, so its own value is still judged (`--no-auth --api-key x`).
 */
function replaceFlagValues(text: string, re: RegExp, judge: (flag: string, value: string, offset: number) => boolean): string {
  let out = '';
  let last = 0;
  re.lastIndex = 0;
  for (let m = re.exec(text); m; m = re.exec(text)) {
    const [all, , flag, sep, value] = m;
    const valueAt = m.index + all.length - value.length;
    if (isFlagShaped(value.replace(/^\\*["']|\\*["']$/g, ''))) {
      // resume at the boundary character before it (a separator ending in `=` has none)
      if (/[\s"',]$/.test(sep)) re.lastIndex = valueAt - 1;
      continue;
    }
    if (value === MASK || PROSE_WORD.test(value) || !judge(flag, value, m.index)) continue;
    out += text.slice(last, valueAt) + quotedMask(value);
    last = valueAt + value.length;
  }
  return out + text.slice(last);
}

/** Shared argv rules 2–4 for a short flag's value, given the command before it. */
function shortFlagSecret(flag: string, value: string, command: string): boolean {
  if (keepValue(value)) return false;
  // a separate `-p <value>` is the password only after sshpass (rule 2)
  if (flag === '-p') return isPasswordAfterP(value, SEPARATE_P_CLIENT_IN_TEXT.test(command));
  if (flag === '-k') return isKeyAfterK(value);
  return REDIS_CLI_IN_TEXT.test(command) && isPasswordAfterA(value);
}

/**
 * A label VASO writes before a quoted config value (`Server "auth": …`): the
 * server's name is not a key whose value follows, whatever words it holds.
 */
const SERVER_LABEL = /^(Server "(?:[^"\\\n]|\\.)*": )/;
function withoutLabel(text: string, fn: (rest: string) => string): string {
  const label = SERVER_LABEL.exec(text);
  return label ? label[1] + fn(text.slice(label[1].length)) : fn(text);
}

/**
 * Credentials that ride along inside text a finding quotes — an MCP server
 * URL with a password, `?access_token=` or `#access_token=`, a webhook URL,
 * an `Authorization:` header, `NAME=value` env assignments, `--token` style
 * arguments, `curl -u user:pass` — masked so reports and baselines don't
 * carry them. Only the secret part is replaced; hosts, paths, parameter and
 * variable names stay readable, as do references (`${VAR}`) and placeholders.
 */
export function maskCredentialsInText(text: string): string {
  return withoutLabel(text, maskText);
}

/** MASK inside the quotes, escaped or not, that wrapped a flag's value (`"***"`, `\"***\"`). */
function quotedMask(value: string): string {
  const q = /^(\\*["'])[\s\S]*\1$/.exec(value)?.[1];
  return q && value.length > 2 * q.length ? `${q}${MASK}${q}` : MASK;
}

/** `replacement` inside the escaped quotes that wrapped `value` (`\"***\"`), or alone. */
function escapedQuotes(value: string, replacement: string): string {
  const q = /^(\\+")[\s\S]*\1$/.exec(value)?.[1];
  return q ? `${q}${replacement}${q}` : replacement;
}

/**
 * An address under an address name, `rest` being the text from the value on:
 * a plain address literal, prefixed or not (`TOKEN_URL = f"{HOST}/oauth/token"`),
 * or one passed to `new URL(…)` (`tokenEndpoint = new URL("http://…")`).
 */
function addressValue(name: string, rest: string): boolean {
  if (!URL_NAME.test(name)) return false;
  // the whole value: nothing else (another literal) may follow it
  const lit = /^\s*(?:new\s+URL\s*\(\s*(["'`])([^"'`\n]*)\1\s*(?:,\s*[A-Za-z_$][\w$.]*\s*)?\)|[rRbBuUfF]{0,2}(["'`])([^"'`\n]*)\3)\s*(?:[;,)]|#|\/\/|$)/.exec(rest);
  if (lit === null) return false;
  // `new URL("/oauth/token", BASE)`: a path against a base
  return lit[2] !== undefined ? plainAddress(lit[2]) || /^\/[\w\-./~%]*$/.test(lit[2]) : plainAddress(lit[4]);
}

function maskText(input: string): string {
  // a JWT (`eyJ…`) needs none of [:=@-] around it
  if (!/[:=@-]/.test(input) && !input.includes('eyJ') && !BARE_TOKEN_HINT.test(input)) return input;
  // the argv rules on the commands in the text, words assembled as the shell does
  const text = maskCodeFallbacks(maskCommandCredentials(input));
  const pem = text.includes('-----BEGIN') ? text.replace(PEM_BODY, MASK) : text;
  const jwt = pem.includes('eyJ') ? pem.replace(JWT, MASK) : pem;
  const bare = BARE_TOKEN_HINT.test(jwt)
    ? jwt.replace(BARE_TOKEN, (m) => (keepValue(m) ? m : MASK)).replace(BARE_TOKEN_I, (m) => (keepValue(m) ? m : MASK))
    : jwt;
  const masked = bare
    .replace(URL_IN_TEXT, (url) => {
      const body = trimUrlTail(url);
      // plus what MCP-003 reads as a credential: secret paths (Zapier MCP), random path tokens
      return maskUrl(maskUrlSecrets(body)) + url.slice(body.length);
    })
    .replace(SECRET_HEADER, (m, pre: string, name: string, sep: string, scheme: string | undefined, value: string) =>
      (keepValue(value) ? m : `${pre}${name}${sep}${scheme ?? ''}${MASK}`))
    .replace(SECRET_DASHED_HEADER, (m, pre: string, name: string, sep: string, value: string) =>
      (keepValue(value) ? m : `${pre}${name}${sep}${MASK}`))
    .replace(SECRET_ASSIGN, (m, pre: string, name: string, sep: string, value: string, offset: number, whole: string) =>
      (secretAssignName(name) && !keepValue(value) && !codeValue(value, sep) && !groupedCode(value, sep) && !PROSE_WORD.test(value)
        && !addressValue(name, whole.slice(offset + m.length - value.length)) ? `${pre}${name}${sep}${escapedQuotes(value, MASK)}` : m))
    .replace(USER_PASS_FLAG, (m, pre: string, flag: string, sep: string, user: string, pw: string) =>
      (keepValue(pw) ? m : `${pre}${flag}${sep}${user}:${MASK}`));
  const long = [SECRET_FLAG, CAMEL_SECRET_FLAG].reduce((t, re) => replaceFlagValues(t, re, (_flag, value) => !keepValue(value)), masked);
  const short = replaceFlagValues(long, SHORT_FLAG, (flag, value, at) => shortFlagSecret(flag, value, commandBefore(long, at)));
  // glued `-pX`: after a password client anything stored; elsewhere only a
  // token that is no flag (`-pthread`, `-pedantic`) and looks like a credential
  return replaceFlagValues(short, ATTACHED_P, (_flag, value, at) => {
    if (keepValue(value)) return false;
    const client = PASSWORD_P_CLIENT_IN_TEXT.test(commandBefore(short, at));
    return (client || !isFlagShaped(`-p${value}`)) && isPasswordAfterP(value, client);
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
const SECRET_KEY_VALUE = /(^|[\s"'{,])(["']?)([A-Za-z_][\w.-]{0,127})\2(\s*[:=]\s*(?:[&!][^\s,{}[\]]*\s+)*)("{3}[\s\S]*?"{3}|'{3}[\s\S]*?'{3}|"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|\\+"[^"\\\n]*\\+"|\$\{[^}\s]*\}|(?![{[#])(?:[^\s,#}\]]|#)+)/g;
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
  return withoutLabel(raw, maskLine);
}

function maskLine(raw: string): string {
  // JSON escaped inside a string or a shell argument (`{\"apiKey\":\"…\"}`)
  const unescaped = raw.includes('\\') ? raw.replace(ESCAPED_JSON_PAIR, (m, q1: string, name: string, q2: string, value: string, q3: string) =>
    (isSecretName(name) && !keepValue(value) ? `${q1}${name}${q2}${MASK}${q3}` : m)) : raw;
  const line = maskCodeFallbacks(unescaped);
  const b64 = BASE64_LINE.exec(line);
  if (b64 && /[A-Z]/.test(b64[2]) && /[a-z]/.test(b64[2]) && /\d/.test(b64[2])) return `${b64[1]}${MASK}${b64[3]}`;
  const whole = line.replace(SECRET_LINE_VALUE, (m, pre: string, name: string, sep: string, rest: string) => {
    // a ` #` comment ends the value (found by search: a lazy value before an
    // optional comment group rescans the line per character)
    const hash = rest.search(/\s#/);
    const value = (hash < 0 ? rest : rest.slice(0, hash)).trimEnd();
    if (!isSecretName(name) || keepValue(value) || (sep.includes('=') && codeValue(value, sep)) || addressValue(name, rest)) return m;
    if (sep.includes('=') && groupedCode(value, sep)) return `${pre}${name}${sep}${maskValueText(value)}${rest.slice(value.length)}`;
    return `${pre}${name}${sep}${MASK}${rest.slice(value.length)}`;
  });
  const listed = whole.replace(SECRET_KEY_LIST, (m, pre: string, q: string, name: string, sep: string, items: string) =>
    (isSecretName(name)
      ? `${pre}${q}${name}${q}${sep}[${items.replace(/[^,\s"']+(?:\s+[^,\s"']+)*/g, (v) => (keepValue(v) ? v : MASK))}]`
      : m));
  const masked = listed.replace(SECRET_KEY_VALUE, (m, pre: string, q: string, name: string, sep: string, value: string, offset: number, all: string) => {
    // `name = call(…)` in a source line is code (YAML `name: …` is always a value)
    if (!isSecretName(name) || keepValue(value) || (sep.includes('=') && codeValue(value, sep))) return m;
    if (addressValue(name, all.slice(offset + m.length - value.length))) return m;
    // (identifiers alone — the rest of the line, its literals, masked above)
    if (sep.includes('=') && groupedCode(value, sep)) return /["']/.test(value) ? `${pre}${q}${name}${q}${sep}${maskValueText(value)}` : m;
    const quote = /^["']/.test(value) ? value[0] : '';
    return `${pre}${q}${name}${q}${sep}${quote ? `${quote}${MASK}${quote}` : escapedQuotes(value, MASK)}`;
  });
  return maskText(masked).replace(CUT_TOKEN_TAIL, (m, prefix: string, cut: string) => `${prefix}${MASK}${cut}`);
}

/**
 * A token a check's snippet cut off (`…slice(0, 120)`, ` ...`, `…`): too short
 * to match its pattern any more, so BARE_TOKEN leaves it — its prefix ends the
 * snippet's last word.
 */
// (a Telegram bot token's `<bot id>:` is its prefix)
const CUT_TOKEN_TAIL = new RegExp(String.raw`\b(${[...CUT_PREFIXES, String.raw`\d{8,10}:`].join('|')})[A-Za-z0-9_.$-]{4,}((?: ?\.\.\.|…)?)$`);

/**
 * Whether a config path names a credential: any segment does (`apiKeys.0`,
 * `credentials.db.user`, `env.PIN`) — array indices skipped — unless its
 * last name is a setting about one (`session.timeout`, `max_tokens`).
 */
function isSecretPath(path: string): boolean {
  const names = path.split('.').filter(s => s !== '' && !/^\d+$/.test(s));
  const leaf = names.at(-1);
  if (leaf === undefined || SETTING_NAME.test(leaf)) return false;
  return names.some(n => isSecretName(n));
}

/**
 * A config value quoted in a finding (`name` is its key or dotted path): a
 * string or number under a credential name — or anywhere below one — is
 * masked (references and placeholders stay), an `args` array is masked as
 * argv (the value after `--api-key`), and every other string is masked as text.
 */
export function maskConfigValue(name: string, value: unknown, inherited = false): unknown {
  const secret = inherited || isSecretPath(name);
  if (typeof value === 'string') return secret ? mask(value) : maskCredentialsInText(value);
  if (typeof value === 'number' || typeof value === 'bigint') return secret ? MASK : value;
  if (Array.isArray(value)) {
    if (!secret && /(?:^|\.)args$/.test(name) && isStringArray(value)) return maskArgv(value);
    return value.map(v => maskConfigValue(name, v, secret));
  }
  if (value && typeof value === 'object') {
    const command = (value as { command?: unknown }).command;
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k,
      !secret && k === 'args' && isStringArray(v) ? maskArgv(v, command) : maskConfigValue(k, v, secret)]));
  }
  return value;
}

/** At most this many credential values are collected from one config file. */
const MAX_CREDENTIAL_VALUES = 2000;

/**
 * The credential values a parsed config holds — every string or number
 * maskConfigValue masks whole (each line of a multi-line one, and each word of
 * at least 6 characters: a YAML folded or plain multi-line scalar reads back
 * with its line breaks turned to spaces) — so a line quoted from the file can
 * be masked even where the line alone doesn't show it is a credential (an
 * argv element below its flag, an item of a `secrets:` list, a numeric PIN).
 */
export function credentialValuesIn(data: unknown): string[] {
  const out = new Set<string>();
  const put = (t: string) => {
    if (t.length >= 3 && t !== MASK && out.size < MAX_CREDENTIAL_VALUES) out.add(t);
  };
  const add = (v: string) => {
    for (const line of v.split(/\r?\n/)) {
      const t = line.trim();
      put(t);
      if (/\s/.test(t)) {
        for (const word of t.split(/\s+/)) if (word.length >= 6 && !keepValue(word)) put(word);
      }
    }
  };
  const visit = (orig: unknown, masked: unknown): void => {
    if (out.size >= MAX_CREDENTIAL_VALUES) return;
    if (masked === MASK && (typeof orig === 'string' || typeof orig === 'number' || typeof orig === 'bigint')) {
      add(String(orig));
    } else if (Array.isArray(orig) && Array.isArray(masked)) {
      orig.forEach((o, i) => visit(o, masked[i]));
    } else if (orig && typeof orig === 'object' && masked && typeof masked === 'object') {
      for (const [k, v] of Object.entries(orig)) visit(v, (masked as Record<string, unknown>)[k]);
    }
  };
  visit(data, maskConfigValue('', data));
  return [...out];
}

const escapeRegex = (s: string): string => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/** A character escape inside a quoted string: JSON/JS `\uXXXX`, YAML/Python `\xNN` and `\UXXXXXXXX` (and `\\`, kept). */
const CHAR_ESCAPE = /\\(?:u([0-9A-Fa-f]{4})|x([0-9A-Fa-f]{2})|U([0-9A-Fa-f]{8})|\\)/g;

/**
 * `re` run over the line with its character escapes decoded, each match
 * masked in the line as written: a value spelled `"Hunter2"` in an
 * ASCII-escaped JSON file is the value `Hunter2`.
 */
function maskDecoded(line: string, re: RegExp): string {
  // the decoded text, and for each decoded character the raw offset it starts at
  let decoded = '';
  const at: number[] = [];
  let last = 0;
  for (const m of line.matchAll(CHAR_ESCAPE)) {
    for (let k = last; k < m.index; k++) { decoded += line[k]; at.push(k); }
    const hex = m[1] ?? m[2] ?? m[3];
    const ch = hex === undefined ? m[0] : String.fromCodePoint(Math.min(parseInt(hex, 16), 0x10ffff));
    for (let k = 0; k < ch.length; k++) { decoded += ch[k]; at.push(m.index); }
    last = m.index + m[0].length;
  }
  for (let k = last; k < line.length; k++) { decoded += line[k]; at.push(k); }
  at.push(line.length);
  const spans: Array<[number, number]> = [];
  for (const m of decoded.matchAll(re)) spans.push([at[m.index], at[m.index + m[0].length]]);
  let out = line;
  for (const [a, b] of spans.reverse()) out = `${out.slice(0, a)}${MASK}${out.slice(b)}`;
  return out;
}

/**
 * A masker replacing each of `values` (credentialValuesIn) wherever it
 * stands as a whole word in a line — also JSON-escaped (`pw\"x`), and spelled
 * with character escapes (`Hunter2`, `\x48unter2`).
 */
export function knownValueMasker(values: readonly string[]): (line: string) => string {
  const forms = new Set<string>();
  for (const v of values) {
    forms.add(v);
    forms.add(JSON.stringify(v).slice(1, -1));
  }
  if (forms.size === 0) return line => line;
  const alternatives = [...forms].sort((a, b) => b.length - a.length).map(escapeRegex).join('|');
  const re = new RegExp(`(?<![A-Za-z0-9_])(?:${alternatives})(?![A-Za-z0-9_])`, 'g');
  return line => {
    const out = line.replace(re, MASK);
    return /\\[uxU][0-9A-Fa-f]/.test(out) ? maskDecoded(out, re) : out;
  };
}

/** `name = …` / `name: …` / `"name": …` opening a value, optionally a declaration (`const password = (`). */
const VALUE_OPENER = /^(\s*)(?:-\s+)?(?:(?:export\s+)?(?:const|let|var)\s+)?(["']?)([A-Za-z_$][\w.$-]*)\2\s*(?::=|[:=])\s*(.*)$/;
/** A `key: value` / `"key": value` / `key = value` line inside a block. */
const KEYED_LINE = /^(\s*(?:-\s+)?(["']?)[A-Za-z_$][\w.$-]*\2\s*(?::=|[:=])\s*)(.+)$/;
const QUOTED = /"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'/g;

/** Net opening brackets on a line, quoted strings skipped. */
function bracketDepth(line: string): number {
  let depth = 0;
  for (const ch of line.replace(QUOTED, '""')) {
    if (ch === '[' || ch === '(' || ch === '{') depth++;
    else if (ch === ']' || ch === ')' || ch === '}') depth--;
  }
  return depth;
}

/**
 * An environment-variable lookup opening right before a quoted string
 * (`os.environ.get(`, `os.environ[`, `getenv(`, `process.env[`, `ENV.fetch(`,
 * `env::var(`): the string is the variable's name, not a credential.
 */
const ENV_LOOKUP_BEFORE = /(?:\benviron(?:\.get|\.setdefault)?|\b[gG]etenv|\bprocess\.env|\bENV(?:\.fetch)?|\benv::var(?:_os)?|\bDeno\.env\.get)\s*[[(]\s*$/;

/** A value's text masked: quoted strings' contents, else the bare words (brackets, commas and `- ` kept). */
function maskValueText(text: string): string {
  if (/["']/.test(text)) {
    return text.replace(QUOTED, (q, offset: number) => (keepValue(q.slice(1, -1)) || ENV_LOOKUP_BEFORE.test(text.slice(0, offset)) ? q : `${q[0]}${MASK}${q[0]}`));
  }
  return text.replace(/[^\s,[\](){}]+(?:[ \t]+[^\s,[\](){}]+)*/g, (w) => (w === '-' || keepValue(w) ? w : (w.startsWith('- ') ? `- ${MASK}` : MASK)));
}

type ContinuationBlock = 'brackets' | 'indented' | 'scalar' | 'triple';

/** A line of a credential's value continued from the line naming it. */
function maskContinuation(line: string, block: ContinuationBlock): string {
  const indent = /^\s*/.exec(line)![0];
  const body = line.slice(indent.length);
  if (body === '') return line;
  if (block === 'scalar') return `${indent}${MASK}`;
  // the closing line of a `"""` string keeps its quotes and what follows them
  if (block === 'triple') return /^(.*?)("""|''')/.test(body) ? `${indent}${body.replace(/^.*?("""|''')/, (m, q: string) => (m === q ? q : `${MASK}${q}`))}` : `${indent}${MASK}`;
  // a key inside the value (a nested object): its value is the credential's
  const keyed = KEYED_LINE.exec(line);
  if (keyed) return `${keyed[1]}${maskValueText(keyed[3])}`;
  return `${indent}${maskValueText(body)}`;
}

/**
 * The lines of a file that continue a credential's value from the line naming
 * it: `API_KEYS = [` / `password = (` / `"password":` then the value on the
 * next lines, a YAML block or multi-line plain scalar under `api_key:`, a
 * TOML `"""` string. Such a line alone shows no credential name, so a
 * declarative rule quoting it would quote the secret; this masks the values
 * on them (brackets and punctuation kept). Works on any text — a skill file
 * has no parsed config to take the values from.
 */
/** At most this many lines continue one credential value. */
const MAX_CONTINUED_LINES = 200;

export function continuationMasker(lines: readonly string[]): (index: number, line: string) => string {
  const blocks = new Map<number, ContinuationBlock>();
  // a credential's value expression left open at the end of the line
  // (`token = os.getenv("X") or \`, `apiKey = getKey() ||`, `connect(password=(`):
  // the lines up to where it closes; returns the last one
  const openExpression = (i: number): number => {
    if (!credentialValueContinues(lines[i])) return i;
    let depth = Math.max(0, bracketDepth(lines[i]));
    let j = i + 1;
    for (; j < lines.length && j <= i + MAX_CONTINUED_LINES; j++) {
      blocks.set(j, 'brackets');
      depth = Math.max(0, depth + bracketDepth(lines[j]));
      if (depth === 0 && !OPEN_TAIL.test(lines[j].replace(/\s+(?:#|\/\/).*$/, ''))) break;
    }
    return Math.min(j, lines.length - 1);
  };
  for (let i = 0; i < lines.length; i++) {
    const open = VALUE_OPENER.exec(lines[i]);
    if (!open || !isSecretName(open[3])) { i = openExpression(i); continue; }
    const keyIndent = open[1].length;
    const rest = open[4].replace(/\s+(?:#|\/\/).*$/, '').trim();
    if (rest.startsWith('"""') || rest.startsWith("'''")) {
      const q = rest.slice(0, 3);
      if (rest.slice(3).includes(q)) continue;
      let j = i + 1;
      for (; j < lines.length && !lines[j].includes(q); j++) blocks.set(j, 'triple');
      if (j < lines.length) blocks.set(j, 'triple');
      i = j;
      continue;
    }
    const depth = bracketDepth(rest);
    if (depth > 0) {
      let d = depth;
      let j = i + 1;
      for (; j < lines.length && d > 0; j++) {
        blocks.set(j, 'brackets');
        d += bracketDepth(lines[j]);
      }
      i = j - 1;
      continue;
    }
    const scalar = /^[|>][-+]?\d*$/.test(rest);
    if (rest !== '' && !scalar) { i = openExpression(i); continue; }
    // the value on the lines indented below the name (YAML), or on the next line (`"password":` then the value)
    let j = i + 1;
    for (; j < lines.length; j++) {
      if (lines[j].trim() === '') continue;
      if (/^\s*/.exec(lines[j])![0].length <= keyIndent) break;
      // a nested mapping's keys are names, not the value
      if (!scalar && KEYED_LINE.test(lines[j])) continue;
      blocks.set(j, scalar ? 'scalar' : 'indented');
      // a quoted value (JSON) is one line
      if (!scalar && /^\s*["']/.test(lines[j])) { j++; break; }
    }
    i = j - 1;
  }
  return (index, line) => {
    const block = blocks.get(index);
    return block ? maskContinuation(line, block) : line;
  };
}

/** Flags whose value is the next argv element. */
const VALUE_FLAG = new RegExp(String.raw`^--?(?:[a-z][\w-]*?[-_])?${FLAG_WORD}$`, 'i');
const CAMEL_VALUE_FLAG = new RegExp(String.raw`^--?${CAMEL_FLAG_WORD}$`);

/**
 * An argv array: each element masked as text, and the element after a
 * credential flag (`--token`, `-p`, `--password`, `-u`) masked as its value —
 * as separate argv elements they never meet in one string.
 */
function maskArgv(args: string[], command?: unknown): string[] {
  const out = args.map(a => maskCredentialsInText(a));
  // a MySQL/MariaDB client, `sshpass` or `redis-cli` as the server's command
  // or earlier in the array (shared argv rules 2 and 4); a glued `-pX` after any of the first two
  const cmd = typeof command === 'string' ? command : '';
  const clientAt = args.findIndex(isPasswordClient);
  const redisAt = args.findIndex(isRedisCli);
  const clientBefore = (i: number): boolean => isPasswordClient(cmd) || (clientAt >= 0 && clientAt < i);
  // a separate `-p <value>` is the password only after sshpass (`mysql -p app_db` names the database)
  const sshpassAt = args.findIndex(isSeparatePasswordClient);
  const sshpassBefore = (i: number): boolean => isSeparatePasswordClient(cmd) || (sshpassAt >= 0 && sshpassAt < i);
  const redisBefore = (i: number): boolean => isRedisCli(cmd) || (redisAt >= 0 && redisAt < i);
  for (let i = 0; i + 1 < out.length; i++) {
    const flag = args[i];
    const next = out[i + 1];
    // the next element is a value unless it is flag-shaped (rule 1)
    const isValue = next !== MASK && !isFlagShaped(next) && !keepValue(next);
    if (flag === '-p') {
      if (isValue && isPasswordAfterP(args[i + 1], sshpassBefore(i))) out[i + 1] = MASK;
    } else if (flag === '-k') {
      if (isValue && isKeyAfterK(args[i + 1])) out[i + 1] = MASK;
    } else if (flag === '-a') {
      if (isValue && redisBefore(i) && isPasswordAfterA(args[i + 1])) out[i + 1] = MASK;
    } else if (VALUE_FLAG.test(flag) || CAMEL_VALUE_FLAG.test(flag)) {
      if (isValue) out[i + 1] = MASK;
    } else if (/^(?:-u|--user|--proxy-user)$/.test(flag)) {
      out[i + 1] = next.replace(/^([^:]+):(.+)$/, (m, user: string, pw: string) => (keepValue(pw) ? m : `${user}:${MASK}`));
    } else if (/^(?:-e|--env)$/.test(flag)) {
      out[i + 1] = next.replace(/^([A-Za-z_][A-Za-z0-9_]*)=(.+)$/, (m, name: string, v: string) => (secretAssignName(name) && !keepValue(v) ? `${name}=${MASK}` : m));
    }
  }
  // `mysql … -pSECRET` as its own element: the client is another element
  for (const [i, a] of args.entries()) {
    const p = /^-p(.+)$/s.exec(a)?.[1];
    const client = clientBefore(i);
    if (p && !keepValue(p) && (client || !isFlagShaped(a)) && isPasswordAfterP(p, client)) out[i] = `-p${MASK}`;
  }
  // other clients' password options, a password echoed into stdin (shared argv rules 7 and 8)
  const argv = cmd ? [cmd, ...args] : args;
  for (const h of clientAndStdinHits(argv)) {
    const i = h.tok - (cmd ? 1 : 0);
    if (i >= 0) out[i] = maskCredentialsInText(args[i].slice(0, h.from)) + MASK + maskCredentialsInText(args[i].slice(h.to));
  }
  return out;
}

/**
 * An evidence snippet quotes a line of a config or source file, where a
 * credential is written `"key": "value"` / `key: value` as often as
 * `KEY=value` — a one-line JSON file puts every key a check didn't match on
 * the same line as the one it did. Masking can lengthen a snippet the engine
 * cut to MAX_SNIPPET: it is cut again, after masking — a cut before it could
 * leave a value the masker no longer recognizes.
 */
function maskString(value: string, key: string): string {
  if (key !== 'snippet') return maskCredentialsInText(value);
  const masked = maskCredentialsInLine(value);
  // (a snippet the engine cut is MAX_SNIPPET plus its ` ...` marker)
  return masked.length > MAX_SNIPPET + ' ...'.length ? truncateSnippet(masked, MAX_SNIPPET) : masked;
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
    const command = (value as { command?: unknown }).command;
    for (const [k, v] of Object.entries(value)) {
      // a server's argv is judged with its command (`command: "mysql"`, `args: ["-pX"]`)
      out[k] = k === 'configFiles' ? v : k === 'args' && isStringArray(v) ? maskArgv(v, command) : maskCredentialsDeep(v, k);
    }
    return out as T;
  }
  return value;
}

function maskMap(map: Record<string, unknown>): Record<string, unknown> {
  return Object.fromEntries(Object.entries(map).map(([k, v]) => [k, typeof v === 'string' && !keepValue(v) ? maskValue(v) : v]));
}

export function reportReplacer(this: unknown, key: string, value: unknown): unknown {
  if (typeof value === 'string') return maskString(value, key);
  if (isStringArray(value)) return maskArgv(value, key === 'args' ? (this as { command?: unknown } | undefined)?.command : undefined);
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

/**
 * Pretty-printed JSON with config contents stripped and MCP secrets masked.
 * Bidi, zero-width, tag and C1 characters from scanned text are written as
 * `\uXXXX` escapes (values unchanged) — every JSON VASO writes: scan and
 * detect reports, multi-host lists, baselines.
 */
export function toReportJson(value: unknown): string {
  return escapeJsonUnsafe(JSON.stringify(value, reportReplacer, 2));
}
