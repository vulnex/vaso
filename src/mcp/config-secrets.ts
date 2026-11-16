import { API_KEY_PATTERNS, isPathValue, isPlaceholderSecret, snippetAround } from '../core/patterns.js';
import {
  CLIENT_PASSWORD_VAR, USER_PASS_FLAGS, isFlagShaped, isKeyAfterK, isPasswordAfterA, isPasswordAfterP, isPasswordClient, isRedisCli, isSeparatePasswordClient,
  isUserPassClient, isUnstoredValue as notASecret, PASSWORD_P_CLIENT_IN_TEXT, REDIS_CLI_IN_TEXT, SEPARATE_P_CLIENT_IN_TEXT, userPassword, looksLikeCredential as looksLikeSecret,
} from './argv-rules.js';
import { shannonEntropy } from '../analyzers/entropy.js';
import { shellCommandWrapper } from './shell-wrapper.js';
import { commandName } from './package-pin.js';
import { commandWords, scriptCommands, shellWords } from './script-command.js';

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
  /** How it is written: after a credential flag, in a header, a URL, a connection string, an assignment, inline JSON, or a bare token. */
  via?: 'flag' | 'header' | 'url' | 'connection' | 'assignment' | 'json' | 'token';
}

const MASK = '***';

/** Flags whose value is a credential (`--token x`, `--api-key=x`, `--password x`, `--aws-secret-access-key x`). */
const CREDENTIAL_FLAG = /^--?(?:[a-z][\w-]*?[-_])?(?:access[_-]?token|auth[_-]?token|token|api[_-]?key|apikey|(?:secret|private|access|signing|encryption|master)[_-]?key|pat|secret|client[_-]?secret|password|passwd|pass|pwd|pw|credentials?|bearer)$/i;
/** The same in camelCase (`--apiToken`, `--githubToken`, `--oauth2Bearer`, `--secretKey`): case-sensitive, so `--monkey` isn't one. */
const CAMEL_CREDENTIAL_FLAG = /^--?[a-z][a-z0-9]*(?:[A-Z][a-z0-9]*)*?(?:AccessToken|AuthToken|Token|ApiKey|Apikey|(?:Secret|Private|Access|Signing|Encryption|Master)Key|Pat|Secret|ClientSecret|Password|Passwd|Pwd|Credentials?|Bearer)$/;
/** A flag whose value is a credential, in any of the spellings above. */
export function isCredentialFlag(flag: string): boolean {
  return CREDENTIAL_FLAG.test(flag) || CAMEL_CREDENTIAL_FLAG.test(flag);
}
/** `NAME=value` assignment (docker `-e`, `env K=V cmd`, helm `--set auth.password=x`). */
const ASSIGNMENT = /^([A-Za-z_][\w.-]*)=(.+)$/s;
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

/** `text` with every copy of `value` replaced; just the mask when the value isn't found verbatim. */
function maskIn(text: string, value: string): string {
  return text.includes(value) ? text.split(value).join(MASK) : MASK;
}

/**
 * Secrets in one URL: userinfo, credential query parameters, token path
 * segments. Any `scheme://` URL has userinfo and parameters — a database or
 * broker connection URL (`postgresql://app:<pw>@db`, `redis://:<pw>@cache`,
 * `mongodb+srv://`, `amqp://`) carries its password there; path tokens are
 * judged on web URLs only.
 */
export function findUrlSecrets(url: string, location = 'url'): ConfigSecret[] {
  const found = urlSecrets(url, location);
  if (found.length === 0) return found;
  // one masked copy of the URL for all of them
  const masked = maskValues(url, found.map((f) => f.value));
  return found.map((f) => ({ ...f, masked: masked.text === undefined ? MASK : elementWindow(masked.text, masked.firstAt.get(f.value)) }));
}

function urlSecrets(url: string, location: string): ConfigSecret[] {
  const out: ConfigSecret[] = [];
  const seen = new Set<string>();
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(url)) return out;
  let parsed: URL | undefined;
  try {
    parsed = new URL(url);
  } catch {
    parsed = undefined;
  }
  const add = (value: string, kind: string) => {
    if (!value || notASecret(value) || seen.has(value)) return;
    seen.add(value);
    out.push({ location, kind, masked: '', value, via: 'url' });
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
  if (!parsed) return out;

  for (const [name, value] of parsed.searchParams) {
    const known = knownToken(value);
    if (known) {
      add(rawParam(url, name) ?? value, `${known.name} in URL query parameter "${name}"`);
    } else if (SECRET_PARAM.test(name) && value.length >= 8
      // a password may be any text; a key or token is random (`?key=documentation` is a word)
      && (/^(?:password|pass|pwd)$/i.test(name) || looksLikeSecret(value))) {
      add(rawParam(url, name) ?? value, `credential in URL query parameter "${name}"`);
    }
  }

  // `#access_token=…` (OAuth implicit-flow style): sent nowhere by HTTP, but
  // stored and logged with the URL like any other part of it
  for (const [name, value] of fragmentParams(url)) {
    const known = knownToken(value);
    if (known) add(value, `${known.name} in URL fragment "${name}"`);
    else if (SECRET_PARAM.test(name) && value.length >= 8 && (/^(?:password|pass|pwd)$/i.test(name) || looksLikeSecret(value))) {
      add(value, `credential in URL fragment "${name}"`);
    }
  }

  if (!/^(?:https?|wss?):$/.test(parsed.protocol)) return out;
  const path = rawPath(url);
  const host = parsed.hostname.toLowerCase();
  const hostPath = credentialPath(host, path);
  if (hostPath) add(hostPath.value, hostPath.kind);
  // Document and file IDs on content hosts (a Google Doc's `/d/<id>`, a
  // Notion page, a Figma file key) name a resource that still needs the
  // viewer's own sign-in: not a credential. Known token formats still count.
  const contentHost = CONTENT_ID_HOST.test(host);
  const endpointPath = ENDPOINT_HOST.test(host) || ENDPOINT_SEGMENT.test(path);
  let previous = '';
  const segments = path.split('/');
  for (const [index, rawSegment] of segments.entries()) {
    const after = previous;
    previous = rawSegment;
    const next = segments[index + 1]?.split(';')[0] ?? '';
    // `;jsessionid=…` matrix parameters ride on a segment
    const [segment, ...matrix] = rawSegment.split(';');
    for (const param of matrix) {
      const eq = param.indexOf('=');
      const value = eq > 0 ? param.slice(eq + 1) : '';
      if (eq > 0 && /^(?:jsessionid|phpsessid|sid|session(?:[_-]?id)?|token|auth|key|api[_-]?key)$/i.test(param.slice(0, eq)) && value.length >= 8) {
        add(value, `session or credential in URL path parameter "${param.slice(0, eq)}"`);
      }
    }
    if (!segment || hostPath?.value.split('/').includes(segment)) continue;
    // Telegram Bot API: https://api.telegram.org/bot<id>:<secret>/method
    const bot = /^bot(\d{6,}:[A-Za-z0-9_-]{30,})$/.exec(segment);
    if (bot) { add(bot[1], 'Telegram Bot token in URL path'); continue; }
    const known = knownToken(segment);
    if (known) { add(known.token, `${known.name} in URL path`); continue; }
    // Zapier's older MCP key (`actions.zapier.com/mcp/sk-ak-…/sse`), under any host
    if (/^sk-ak-[A-Za-z0-9]{20,}$/.test(segment)) { add(segment, 'Zapier MCP API key in URL path'); continue; }
    if (/^eyJ[\w-]{8,}\.eyJ[\w-]{8,}\.[\w-]*$/.test(segment)) { add(segment, 'JWT in URL path'); continue; }
    if (contentHost) continue;
    if (randomPathSegment(segment)) { add(segment, 'random token in URL path (a capability URL: whoever has it can use the server)'); continue; }
    // A hex token is also a commit SHA or a content digest: only on an MCP
    // endpoint or webhook is it the key to the server
    // and only as the key position itself: the last segment, or the one just
    // before the endpoint (`/<key>/sse`) — not a resource ID under a noun
    // (`/projects/<id>/sse`, a commit under `/raw/<sha>/mcp`)
    const keyPosition = !next || ENDPOINT_TAIL.test(next);
    if (endpointPath && keyPosition && !DIGEST_PARENT.test(after) && !RESOURCE_PARENT.test(after)
      && /^(?=.*[a-f])[0-9a-f]{32,}$/.test(segment)) add(segment, 'hex token in MCP/webhook URL path');
  }
  return out;
}

/** Content hosts whose path IDs are documents/files, not credentials. */
const CONTENT_ID_HOST = /(?:^|\.)(?:docs\.google\.com|drive\.google\.com|notion\.so|notion\.site|figma\.com|airtable\.com|youtube\.com|youtu\.be|github\.com|gitlab\.com|wikipedia\.org)$/;
/** An MCP server or webhook endpoint: where a path token is the access key. */
const ENDPOINT_HOST = /(?:^|[.-])(?:mcp|hooks?|webhooks?)(?:[.-]|$)/;
/** Segments a commit SHA or content digest follows (`/commit/<sha>`, `/blobs/<digest>`). */
const DIGEST_PARENT = /^(?:commits?|repos?|blobs?|trees?|objects?|sha\d*|digests?|revisions?|refs|tags?|releases?|builds?|artifacts?)$/i;
const ENDPOINT_SEGMENT = /\/(?:mcp|sse|hooks?|webhooks?|triggers?|catch)(?:\/|$)/i;
/** The segment after a key in an endpoint URL (`/<key>/sse`). */
const ENDPOINT_TAIL = /^(?:mcp|sse|messages?|stream|events?|rpc)$/i;
/** Parents whose child segment is a resource ID, not a key (`/projects/<id>/sse`). */
const RESOURCE_PARENT = /^(?:projects?|repos?|orgs?|organi[sz]ations?|teams?|workspaces?|users?|accounts?|items?|documents?|docs?|files?|spaces?|apps?|sites?|databases?|tables?|raw|ids?)$/i;

/**
 * Hosts whose URL path is itself the credential:
 *  - Zapier MCP `https://mcp.zapier.com/api/mcp/s/<secret>/mcp` ("treat this
 *    URL like a password", docs.zapier.com/mcp) and the older
 *    `https://actions.zapier.com/mcp/<key>/sse`
 *  - Slack incoming webhooks `https://hooks.slack.com/services/T…/B…/<secret>`
 *  - Discord webhooks `https://discord.com/api/webhooks/<id>/<token>`
 *  - Zapier catch hooks `https://hooks.zapier.com/hooks/catch/<id>/<key>/`
 */
function credentialPath(host: string, path: string): { value: string; kind: string } | undefined {
  let m: RegExpExecArray | null;
  if (/(^|\.)zapier\.com$/.test(host)
    && (m = /^\/api\/mcp\/s\/([^/?#]{8,})/.exec(path) ?? /^\/mcp\/([^/?#]{8,})\/(?:sse|mcp)\b/.exec(path))) {
    return { value: m[1], kind: 'Zapier MCP server secret in URL path' };
  }
  // Zapier catch hooks: https://hooks.zapier.com/hooks/catch/<account>/<key>/
  if (/(^|\.)hooks\.zapier\.com$/.test(host) && (m = /^\/hooks\/catch\/\d+\/([^/?#]+)/.exec(path))) {
    return { value: m[1], kind: 'Zapier webhook key in URL path' };
  }
  if (/(^|\.)hooks\.slack\.com$/.test(host) && (m = /^\/(?:services|workflows|triggers)\/([^?#]+)/.exec(path))) {
    return { value: m[1].replace(/\/+$/, ''), kind: 'Slack webhook secret in URL path' };
  }
  if (/(^|\.)(?:discord|discordapp)\.com$/.test(host) && (m = /^\/api\/webhooks\/[^/]+\/([^/?#]+)/.exec(path))) {
    return { value: m[1], kind: 'Discord webhook token in URL path' };
  }
  // Microsoft Teams / Office 365 incoming webhooks:
  // https://<tenant>.webhook.office.com/webhookb2/<group>@<tenant>/IncomingWebhook/<key>/<owner>
  if (/(^|\.)(?:webhook\.)?office(?:365)?\.com$/.test(host) && (m = /\/IncomingWebhook\/([^/?#]+)/i.exec(path))) {
    return { value: m[1], kind: 'Microsoft Teams webhook key in URL path' };
  }
  return undefined;
}

/**
 * A path segment that is a random token rather than a name: 24+ characters
 * of base64/base62 (also `.`, `~` and `%XX` escapes) in both cases with
 * digits and near-maximal entropy, that doesn't split into words
 * (`Model_Context_Protocol_Specification2025`, `Package-Name_Version2Beta3`).
 * UUIDs and hex IDs (resource IDs) are single-case.
 */
function randomPathSegment(segment: string): boolean {
  if (segment.length < 24 || !/^(?:[A-Za-z0-9_+=.~-]|%[0-9A-Fa-f]{2})+$/.test(segment)) return false;
  if (!/[A-Z]/.test(segment) || !/[a-z]/.test(segment) || !/[0-9]/.test(segment)) return false;
  if (segment.split(/[-_.~]|%[0-9A-Fa-f]{2}/).every(p => /^(?:[A-Z]?[a-z]{2,}|[A-Z]{2,}(?![a-z])|\d+)*$/.test(p))) return false;
  return shannonEntropy(segment) >= Math.min(4.5, Math.log2(segment.length) - 0.5);
}

/** The URL's path exactly as written (the parser percent-encodes some characters). */
function rawPath(url: string): string {
  const rest = url.replace(/^[a-z][a-z0-9+.-]*:\/\/[^/?#]*/i, '');
  return rest.split(/[?#]/)[0];
}

/** `name=value` pairs of a URL fragment, raw. */
function fragmentParams(url: string): Array<[string, string]> {
  const hash = url.indexOf('#');
  if (hash < 0) return [];
  const out: Array<[string, string]> = [];
  for (const pair of url.slice(hash + 1).split(/[&;]/)) {
    const eq = pair.indexOf('=');
    if (eq <= 0) continue;
    let n = pair.slice(0, eq);
    try { n = decodeURIComponent(n); } catch { /* keep raw */ }
    out.push([n, pair.slice(eq + 1)]);
  }
  return out;
}

/** Header names whose value is a credential (`Authorization`, `X-Api-Key`, `Api-Key`, `X-Auth-Token`). */
const SECRET_HEADER_NAME = /^(?:(?:proxy-)?authorization|x-(?=[\w-]*?(?:key|token|secret|auth))[\w-]*|api[_-]?key|[\w-]*[_-](?:token|secret))$/i;

/**
 * What a static header value is when it is a stored credential (`Bearer
 * <token>`, `X-Api-Key: <key>`): a known token format or a random-looking
 * value under a credential header name. Undefined for references
 * (`Bearer ${TOKEN}`), placeholders and ordinary header values.
 */
export function headerSecret(name: string, value: string): string | undefined {
  if (/^\s*cookie\s*$/i.test(name)) return cookieSecrets(value).length > 0 ? `session cookie in ${name} header` : undefined;
  const scheme = /^\s*(bearer|basic|token|bot)\s+/i.exec(value);
  const v = value.slice(scheme?.[0].length ?? 0).trim();
  if (notASecret(v)) return undefined;
  const known = knownToken(v);
  if (known) return `${known.name} in ${name} header`;
  if ((scheme || SECRET_HEADER_NAME.test(name.trim())) && looksLikeSecret(v)) {
    return scheme ? `${scheme[1][0].toUpperCase()}${scheme[1].slice(1).toLowerCase()} credential in ${name} header` : `credential in ${name} header`;
  }
  return undefined;
}

/** `url` with every credential `findUrlSecrets` finds in it replaced by `***`. */
export function maskUrlSecrets(url: string): string {
  let masked = url;
  for (const s of findUrlSecrets(url)) masked = masked.split(s.value).join(MASK);
  return masked;
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

/**
 * `password=` / `Pwd=` / `AccountKey=` pairs of a connection string or DSN —
 * ADO.NET / ODBC `Server=db;User Id=sa;Password=<pw>;`, libpq
 * `host=db user=app password=<pw>`, Azure `AccountKey=<key>`.
 */
// (no `\s*` after the boundary: from every space of a long blank run it rescanned the rest)
const CONNECTION_PAIR = /(?:^|[;\s])(password|pwd|passwd|accountkey|sharedaccesskey|sharedsecretvalue)\s*=\s*('[^']*'|"[^"]*"|[^;\s'"]+)/gi;

/** `[name, value]` of each credential in a connection string (two or more `k=v` pairs). */
function connectionSecrets(text: string): Array<[string, string]> {
  if (!text.includes('=') || (text.match(/(?:^|[;\s])[A-Za-z][\w ]{0,40}?=/g) ?? []).length < 2) return [];
  const out: Array<[string, string]> = [];
  for (const m of text.matchAll(CONNECTION_PAIR)) {
    const value = m[2].replace(/^(['"])(.*)\1$/s, '$2');
    if (value.length >= 4 && !notASecret(value)) out.push([m[1], value]);
  }
  return out;
}

/** The session values of a `Cookie:` header (`session=<v>; theme=dark`): long and random, or under a session/auth name. */
function cookieSecrets(value: string): string[] {
  const out: string[] = [];
  for (const pair of value.split(';')) {
    const eq = pair.indexOf('=');
    if (eq <= 0) continue;
    const name = pair.slice(0, eq).trim();
    const v = pair.slice(eq + 1).trim();
    if (notASecret(v)) continue;
    if (looksLikeSecret(v) || (/sess|auth|token|sid|jwt|login/i.test(name) && v.length >= 8)) out.push(v);
  }
  return out;
}

/** `Cookie: <pairs>` as an argument. */
const COOKIE_ARG = /^\s*cookie\s*:(.*)$/is;
/** A vendor header argument named for a credential (`Ocp-Apim-Subscription-Key: x`, `Private-Token: x`). */
const VENDOR_HEADER_ARG = /^\s*([A-Za-z][A-Za-z0-9]*(?:-[A-Za-z0-9]+)*-(?:key|token|secret))\s*:\s*(\S+)\s*$/i;

/**
 * Secrets in one configured value — an env or header value rather than an
 * argument: a connection URL with a password (`DATABASE_URL=postgres://…`)
 * or a connection string's `Password=` pair.
 */
export function findValueSecrets(value: string, location: string): ConfigSecret[] {
  const v = value.trim();
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(v)) return findUrlSecrets(v, location);
  return connectionSecrets(v).map(([name, secret]) => ({
    location, kind: `${name} in a connection string`, masked: maskIn(v, secret), value: secret, via: 'connection' as const,
  }));
}

/** Runners whose `-p` names the package to install (`npx -p pkg cmd`, `yarn dlx -p pkg`). */
const PACKAGE_P_RUNNERS = new Set(['npx', 'bunx', 'pnpx', 'npm', 'pnpm', 'yarn']);

/** A credential found in an element, before its masked rendering is built. */
interface RawSecret {
  /** The element of the outermost argv the value sits in. */
  at: number;
  value: string;
  kind: string;
  via: ConfigSecret['via'];
  /** Text shown before the element (`--token `), when the flag is its own element. */
  prefix?: string;
}

/** Findings reported per element; the rest are counted in the last one's kind. */
export const MAX_SECRETS_PER_ARG = 50;
/** An element longer than this is shown as a window around the value. */
const MASKED_ELEMENT_CHARS = 300;

/**
 * Secrets in an argv array: credential flags (both `--f v` and `--f=v`, also
 * camelCase and `-p<pw>`), env assignments (also `--env=K=V`, dotted
 * `--set a.password=v`), header and cookie args, URLs of any scheme,
 * connection strings, inline JSON, bare tokens, and the commands of a
 * `sh -c` script. Each element is masked once, with every value found in it.
 */
export function findArgSecrets(args: readonly string[], command?: string): ConfigSecret[] {
  const out: ConfigSecret[] = [];
  for (const [at, list] of byElement(collectArgSecrets(args, command, 0))) {
    const masked = maskValues(args[at] ?? '', list.map((r) => r.value));
    const shown = list.slice(0, MAX_SECRETS_PER_ARG);
    const more = list.length - shown.length;
    shown.forEach((r, n) => {
      const kind = more > 0 && n === shown.length - 1 ? `${r.kind} (+${more} more in this argument)` : r.kind;
      const window = masked.text === undefined ? MASK : elementWindow(masked.text, masked.firstAt.get(r.value));
      out.push({ location: `args[${at}]`, kind, masked: `${r.prefix ?? ''}${window}`, value: r.value, via: r.via });
    });
  }
  return out;
}

/** `args` with every credential `findArgSecrets` finds replaced by `***` in its element. */
export function maskArgSecrets(args: readonly string[], command?: string): string[] {
  const out = [...args];
  for (const [at, list] of byElement(collectArgSecrets(args, command, 0))) {
    if (out[at] !== undefined) out[at] = maskValues(out[at], list.map((r) => r.value)).text ?? MASK;
  }
  return out;
}

function byElement(raw: readonly RawSecret[]): Map<number, RawSecret[]> {
  const map = new Map<number, RawSecret[]>();
  for (const r of raw) {
    const list = map.get(r.at);
    if (list) list.push(r);
    else map.set(r.at, [r]);
  }
  return map;
}

interface TrieNode { next: Map<string, TrieNode>; end?: string }

/**
 * `text` with every copy of every value replaced by `***` in one left-to-right
 * pass (the longest value at each position, through a trie of the values),
 * and where each value's first mask starts. `text` is undefined when a value
 * isn't in the element verbatim (unquoted out of a script): the element can't
 * be shown without it.
 */
function maskValues(text: string, values: readonly string[]): { text: string | undefined; firstAt: Map<string, number> } {
  const root: TrieNode = { next: new Map() };
  for (const v of new Set(values)) {
    if (!v) continue;
    let node = root;
    for (const ch of v) {
      let child = node.next.get(ch);
      if (!child) { child = { next: new Map() }; node.next.set(ch, child); }
      node = child;
    }
    node.end = v;
  }
  const parts: string[] = [];
  const firstAt = new Map<string, number>();
  let length = 0;
  let copied = 0;
  for (let i = 0; i < text.length;) {
    let node: TrieNode | undefined = root;
    let match: string | undefined;
    for (let j = i; j < text.length; j++) {
      node = node.next.get(text[j]);
      if (!node) break;
      if (node.end !== undefined) match = node.end;
    }
    if (match === undefined) { i++; continue; }
    parts.push(text.slice(copied, i));
    length += i - copied;
    if (!firstAt.has(match)) firstAt.set(match, length);
    parts.push(MASK);
    length += MASK.length;
    i += match.length;
    copied = i;
  }
  parts.push(text.slice(copied));
  for (const v of values) if (v && !firstAt.has(v)) return { text: undefined, firstAt };
  return { text: parts.join(''), firstAt };
}

/** A masked element, or the part of a long one around a value's mask. */
function elementWindow(masked: string, at: number | undefined): string {
  if (masked.length <= MASKED_ELEMENT_CHARS) return masked;
  return snippetAround(masked, at ?? 0, MASK.length, MASKED_ELEMENT_CHARS);
}

/** Shell scripts inside shell scripts followed (`sh -c "bash -c 'zsh -c …'"`). */
const MAX_SHELL_DEPTH = 4;
const POSIX_SCRIPT_FLAG = /^-[a-zA-Z]*c[a-zA-Z]*$/;

/**
 * The element holding the script a shell runs: `sh -c '<script>'`,
 * `cmd /c "<command line>"` written as one string, `powershell -Command
 * '<script>'`. undefined when there is none (`cmd /c npx -y pkg` split into
 * elements is read element by element already).
 */
function scriptElement(args: readonly string[], command: string): { at: number; powershell: boolean } | undefined {
  const name = commandName(command).toLowerCase();
  if (name === 'cmd') {
    const flag = args.findIndex((a) => /^\/[ck]$/i.test(a));
    const at = flag + 1;
    return flag >= 0 && at === args.length - 1 && /\s/.test(args[at].trim()) ? { at, powershell: false } : undefined;
  }
  if (name === 'powershell' || name === 'pwsh') {
    const flag = args.findIndex((a) => /^-(?:c|command)$/i.test(a));
    return flag >= 0 && flag + 1 < args.length ? { at: flag + 1, powershell: true } : undefined;
  }
  if (!shellCommandWrapper(command, args)) return undefined;
  const flag = args.findIndex((a) => POSIX_SCRIPT_FLAG.test(a));
  const at = flag < 0 ? -1 : args.findIndex((a, i) => i > flag && !a.startsWith('-'));
  return at < 0 ? undefined : { at, powershell: false };
}

/** PowerShell's `$env:NAME = "value"` as the `NAME=value` the assignment rule reads. */
function powershellWords(words: readonly string[]): string[] {
  const out: string[] = [];
  for (let i = 0; i < words.length; i++) {
    const env = /^\$env:([A-Za-z_]\w*)(=.*)?$/is.exec(words[i]);
    if (env && env[2] !== undefined) out.push(`${env[1]}${env[2]}`);
    else if (env && words[i + 1] === '=' && words[i + 2] !== undefined) { out.push(`${env[1]}=${words[i + 2]}`); i += 2; }
    else out.push(words[i]);
  }
  return out;
}

/**
 * `sh -c "mysql -pX db && curl -u u:X …"`: the script's commands, each read
 * as argv by the same rules (`PGPASSWORD=X psql`, a URL's password, curl
 * `-u`, sshpass `-p`), reported at the script's element. In a script `-p`
 * is judged only after a client whose `-p` is the password, or as a
 * server's own option after a runner's package: `mkdir -p`, `kubectl -p`,
 * `cp -p` are other options.
 */
function shellScriptSecrets(args: readonly string[], command: string | undefined, depth: number): RawSecret[] {
  if (command === undefined || depth >= MAX_SHELL_DEPTH) return [];
  const script = scriptElement(args, command);
  if (!script) return [];
  const { at } = script;
  const out: RawSecret[] = [];
  const seen = new Set<string>();
  for (const stmt of scriptCommands(args[at])) {
    const prog = commandWords(stmt);
    const words = shellWords(stmt);
    const found = [
      ...collectArgSecrets(script.powershell ? powershellWords(words) : words, undefined, depth + 1, true),
      ...(prog.length > 1 ? shellScriptSecrets(prog.slice(1), prog[0], depth + 1) : []),
    ];
    for (const s of found) {
      if (seen.has(s.value)) continue;
      seen.add(s.value);
      out.push({ at, value: s.value, kind: s.kind, via: s.via });
    }
  }
  return out;
}

/** A `-p` value that is a path (also `$VAR/…`, `~/…`) or an id (`myProject2024`, a UUID) — not a password. */
function notAPasswordAfterP(value: string): boolean {
  const v = value.replace(/^\\*["']|\\*["']$/g, '');
  if (/^(?:~|\$\{?[A-Za-z_]\w*\}?)(?:[/\\]|$)|^\.{0,2}\/|^[A-Za-z]:\\/.test(v) || isPathValue(v)) return true;
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(v)) return true;
  // words and a number: a project, profile or directory name
  return /^[A-Za-z][a-z]+(?:[A-Z][a-z]+)*[-_]?\d{1,8}$/.test(v);
}

/**
 * The credentials of one argv, each at its element (`script`: the words of
 * a command inside a shell script).
 */
function collectArgSecrets(args: readonly string[], command: string | undefined, depth: number, script = false): RawSecret[] {
  const out: RawSecret[] = [];
  const seen = new Set<string>();
  // a MySQL/MariaDB client or `sshpass` as the command or an earlier element: its `-p` is the password
  // (in a script also inside a word: `(mysql`, `X=$(mysql`, `` `mysql ``)
  const word = (plain: (t: string) => boolean, inText: RegExp) => (a: string): boolean => plain(a) || (script && inText.test(a));
  const clientAt = args.findIndex(word(isPasswordClient, PASSWORD_P_CLIENT_IN_TEXT));
  const afterClient = (i: number): boolean => (command !== undefined && isPasswordClient(command)) || (clientAt >= 0 && clientAt < i);
  // a MySQL/MariaDB client (not sshpass): its `--password=` is the password
  const isMysqlClient = (a: string): boolean => isPasswordClient(a) && !isSeparatePasswordClient(a);
  const mysqlAt = args.findIndex(isMysqlClient);
  const afterMysql = (i: number): boolean => (command !== undefined && isMysqlClient(command)) || (mysqlAt >= 0 && mysqlAt < i);
  // only `sshpass` takes it as a separate element (`mysql -p app_db` names the database)
  const sshpassAt = args.findIndex(word(isSeparatePasswordClient, SEPARATE_P_CLIENT_IN_TEXT));
  const afterSshpass = (i: number): boolean => (command !== undefined && isSeparatePasswordClient(command)) || (sshpassAt >= 0 && sshpassAt < i);
  const redisAt = args.findIndex(word(isRedisCli, REDIS_CLI_IN_TEXT));
  const afterRedis = (i: number): boolean => (command !== undefined && isRedisCli(command)) || (redisAt >= 0 && redisAt < i);
  const curlAt = args.findIndex(isUserPassClient);
  const afterCurl = (i: number): boolean => (command !== undefined && isUserPassClient(command)) || (curlAt >= 0 && curlAt < i);
  // The package runner: the command, or in a script a word of the command (`npx -y pkg -p X`)
  const runnerName = (t: string): string => t.replace(/\\/g, '/').split('/').pop()?.replace(/\.(?:cmd|exe)$/i, '').toLowerCase() ?? '';
  const runnerAt = script ? args.findIndex((a) => PACKAGE_P_RUNNERS.has(runnerName(a))) : -1;
  const runner = runnerAt >= 0 ? runnerName(args[runnerAt]) : runnerName(command ?? '');
  const optionsFrom = runnerAt + 1;
  const rest = args.slice(optionsFrom);
  // The runner's own options come before the package (`npx -y -p pkg cmd`;
  // `npm exec -p pkg`): a `-p` after the package is the server's own
  // (`npx -y mcp-server-mysql -p <pw>`)
  const packageRel = PACKAGE_P_RUNNERS.has(runner)
    ? rest.findIndex((a, i) => !a.startsWith('-') && rest[i - 1] !== '-p' && rest[i - 1] !== '--package'
      && !(['npm', 'pnpm', 'yarn'].includes(runner) && /^(?:exec|x|dlx)$/.test(a) && rest.slice(0, i).every((b) => b.startsWith('-'))))
    : -1;
  const packageAt = packageRel < 0 ? -1 : packageRel + optionsFrom;
  const runnerOption = (i: number): boolean => PACKAGE_P_RUNNERS.has(runner) && i >= optionsFrom && (packageAt < 0 || i < packageAt);
  // In a script `-p` is judged after a password client or as a server's own option only
  const scriptP = (i: number): boolean => !script || afterClient(i) || (PACKAGE_P_RUNNERS.has(runner) && packageAt >= 0 && i > packageAt);
  const add = (i: number, value: string, kind: string, via: ConfigSecret['via'], prefix?: string) => {
    if (!value || notASecret(value) || seen.has(value)) return;
    seen.add(value);
    out.push({ at: i, value, kind, via, prefix });
  };
  const flagValue = (i: number, flag: string, value: string, prefix?: string) => {
    const known = knownToken(value);
    if (known) add(i, known.token, `${known.name} after ${flag}`, 'flag', prefix);
    else if (looksLikeSecret(value)) add(i, value, `credential after ${flag}`, 'flag', prefix);
  };

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    const prev = i > 0 ? args[i - 1] : undefined;

    // curl `-u user:<password>` / `--user=user:<password>` (shared argv rule 5)
    if (prev && USER_PASS_FLAGS.has(prev) && afterCurl(i - 1) && !isFlagShaped(arg)) {
      const pw = userPassword(arg);
      if (pw !== undefined) add(i, pw, `password after ${prev}`, 'flag', `${prev} `);
      continue;
    }
    const userEq = /^(--user|--proxy-user)=(.*)$/s.exec(arg);
    if (userEq && afterCurl(i)) {
      const pw = userPassword(userEq[2]);
      if (pw !== undefined) add(i, pw, `password in ${userEq[1]}`, 'flag');
      continue;
    }
    // `--token <value>`: the value is the next element
    if (prev && isCredentialFlag(prev) && !isFlagShaped(arg)) {
      flagValue(i, prev, arg, `${prev} `);
      continue;
    }
    // `--cookie "session=<value>"` (curl)
    if (prev === '--cookie' && !isFlagShaped(arg)) {
      for (const value of cookieSecrets(arg)) add(i, value, 'session cookie after --cookie', 'header', `${prev} `);
      continue;
    }
    // `-p <password>` (sshpass) — not a port mapping (`-p 8080:80`), a
    // version, a package or a word elsewhere (shared argv rules 1 and 2)
    // A package runner's `-p` is `--package` (`npx -p https://…/x.tgz cmd`):
    // the value is a package spec, judged by the rules below like any argument
    // A path, `$VAR/…`, `~/…` or id value is a directory, project or profile
    if (prev === '-p' && !isFlagShaped(arg) && !(runnerOption(i - 1) && !afterClient(i - 1))) {
      const separate = afterSshpass(i - 1);
      if (scriptP(i - 1) && (separate || !notAPasswordAfterP(arg)) && isPasswordAfterP(arg, separate)) {
        add(i, arg, 'password after -p', 'flag', `${prev} `);
      }
      continue;
    }
    // `-p<password>` glued (`mysql -uroot -pX`)
    const glued = /^-p(.+)$/s.exec(arg)?.[1];
    if (glued && scriptP(i) && (afterClient(i) || !isFlagShaped(arg)) && isPasswordAfterP(glued, afterClient(i))) {
      add(i, glued, 'password glued to -p', 'flag');
      continue;
    }
    // `-k <key>` (rule 3) and `redis-cli -a <password>` (rule 4)
    if (prev === '-k' && !isFlagShaped(arg)) {
      if (isKeyAfterK(arg)) add(i, arg, 'key after -k', 'flag', `${prev} `);
      continue;
    }
    if (prev === '-a' && afterRedis(i - 1) && !isFlagShaped(arg)) {
      if (isPasswordAfterA(arg)) add(i, arg, 'password after redis-cli -a', 'flag', `${prev} `);
      continue;
    }
    // `--api-key <value>` / `--token = <value>` written as one element
    const spaced = /^(--?[A-Za-z][\w-]*)(?:\s*=\s+|\s+(?:=\s*)?)(\S+)$/.exec(arg);
    if (spaced && isCredentialFlag(spaced[1])) {
      flagValue(i, spaced[1], spaced[2]);
      continue;
    }

    // `--token=<value>`; any other `--flag=<value>` is judged by its value
    // (`--header=Authorization: Bearer x`, `--env=K=V`, `--connection-string=…`)
    const flagEq = /^(--?[A-Za-z][\w-]*)=(.+)$/s.exec(arg);
    // `mysql --password=<pw>`: after a MySQL/MariaDB client, whatever is
    // stored there is the password, as glued to -p (a separate value after
    // `--password` is the database, as after -p)
    if (flagEq && flagEq[1] === '--password' && afterMysql(i)) {
      add(i, flagEq[2], 'password in --password', 'flag');
      continue;
    }
    if (flagEq && isCredentialFlag(flagEq[1])) {
      const known = knownToken(flagEq[2]);
      if (known) add(i, known.token, `${known.name} in ${flagEq[1]}`, 'flag');
      else if (looksLikeSecret(flagEq[2])) add(i, flagEq[2], `credential in ${flagEq[1]}`, 'flag');
      continue;
    }
    const text = flagEq ? flagEq[2] : arg;

    // `Server=db;User Id=sa;Password=<pw>`, `host=db password=<pw> dbname=x`
    const conn = connectionSecrets(text);
    if (conn.length > 0) {
      for (const [name, value] of conn) add(i, value, `${name} in a connection string`, 'connection');
      continue;
    }

    // `--header "Authorization: Bearer <value>"` (mcp-remote, supergateway)
    const header = headerArg(text);
    if (header) {
      const [name, value] = header;
      const known = knownToken(value);
      if (known) add(i, known.token, `${known.name} in ${name} header argument`, 'header');
      else if (looksLikeSecret(value)) add(i, value, `credential in ${name} header argument`, 'header');
      continue;
    }
    const cookie = COOKIE_ARG.exec(text);
    if (cookie) {
      for (const value of cookieSecrets(cookie[1])) add(i, value, 'session cookie in Cookie header argument', 'header');
      continue;
    }
    const vendor = VENDOR_HEADER_ARG.exec(text);
    if (vendor) {
      const known = knownToken(vendor[2]);
      if (known) add(i, known.token, `${known.name} in ${vendor[1]} header argument`, 'header');
      else if (looksLikeSecret(vendor[2])) add(i, vendor[2], `credential in ${vendor[1]} header argument`, 'header');
      continue;
    }

    // A URL argument (`mcp-remote https://…?key=…`, `postgresql://u:<pw>@db`)
    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(text)) {
      for (const s of findUrlSecrets(text, `args[${i}]`)) {
        add(i, s.value, s.kind, s.via ?? 'url');
      }
      continue;
    }

    // `-e GITHUB_TOKEN=<value>` / `env OPENAI_API_KEY=<value> node server.js` / `--set auth.password=<value>`
    const assign = ASSIGNMENT.exec(text);
    if (assign) {
      // `DATABASE_URL=postgres://u:<pw>@db`: the URL's own secrets, whatever the name
      if (/^[a-z][a-z0-9+.-]*:\/\//i.test(assign[2])) {
        for (const s of findUrlSecrets(assign[2], `args[${i}]`)) {
          add(i, s.value, s.kind, s.via ?? 'url');
        }
        continue;
      }
      const leaf = assign[1].split('.').pop() ?? assign[1];
      const known = knownToken(assign[2]);
      if (known) add(i, known.token, `${known.name} in ${assign[1]}=`, 'assignment');
      else if (CLIENT_PASSWORD_VAR.test(assign[1]) && !/\s/.test(assign[2]) || SECRET_VAR.test(leaf) && looksLikeSecret(assign[2])) add(i, assign[2], `credential in ${assign[1]}=`, 'assignment');
      continue;
    }

    // Inline JSON (`--config '{"token":"<value>"}'`): a credential-named pair
    if (/[{,]\s*\\*["']/.test(arg)) {
      for (const m of arg.matchAll(INLINE_JSON_PAIR)) {
        const [, name, value] = m;
        if (!JSON_SECRET_NAME.test(name) || /(?:hash(?:ed)?|digest|ttl|expir|type|mode|url|uri|file|path|id)$/i.test(name)) continue;
        const known = knownToken(value);
        if (known) add(i, known.token, `${known.name} in inline JSON "${name}"`, 'json');
        else if (looksLikeSecret(value)) add(i, value, `credential in inline JSON "${name}"`, 'json');
      }
      if (out.some(o => o.at === i)) continue;
    }

    // A bare token standing alone or inside a larger argument
    const known = knownToken(arg);
    if (known) add(i, known.token, known.name, 'token');
  }
  for (const s of shellScriptSecrets(args, command, depth)) {
    if (!seen.has(s.value)) { seen.add(s.value); out.push(s); }
  }
  return out;
}



/** `"name": "value"` (or single quotes) inside an argument holding inline JSON. */
// (quotes may be backslash-escaped: `{\"apiKey\":\"…\"}` inside a shell string)
const INLINE_JSON_PAIR = /\\*["']([A-Za-z_][\w.-]{0,63})\\*["']\s*:\s*\\*["']([^"'\\\s]{8,})\\*["']/g;
const JSON_SECRET_NAME = /(?:token|secret|passw|passphrase|api[_-]?key|apikey|credential|private[_-]?key|auth)/i;
