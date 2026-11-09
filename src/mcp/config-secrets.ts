import { API_KEY_PATTERNS, isPlaceholderSecret, isSecretReference } from '../core/patterns.js';
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

/**
 * A value that is a reference, a placeholder, a secret manager reference, a
 * file or a profile name — never a stored secret. The same predicate as the
 * env-block path (`isSecretReference`), so `--token op://…` and
 * `GITHUB_TOKEN: op://…` are judged alike.
 */
function notASecret(value: string): boolean {
  const v = value.trim().replace(/^['"]|['"]$/g, '');
  if (v === '') return true;
  if (isPlaceholderSecret(v) || isSecretReference(v)) return true;
  // A reference inside the value (`Bearer ${TOKEN}`, `${HOME}/key`) holds nothing literal
  if (/\$\{[^}]+\}|\$env:|\{env:[^}]+\}|%[A-Za-z_][A-Za-z0-9_]*%/i.test(v)) return true;
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

/** `args` with every credential `findArgSecrets` finds replaced by `***` in its element. */
export function maskArgSecrets(args: readonly string[]): string[] {
  const out = [...args];
  for (const s of findArgSecrets(args)) {
    const i = Number(/^args\[(\d+)\]$/.exec(s.location)?.[1]);
    if (Number.isInteger(i) && out[i] !== undefined) out[i] = out[i].includes(s.value) ? out[i].split(s.value).join(MASK) : MASK;
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

    // Inline JSON (`--config '{"token":"<value>"}'`): a credential-named pair
    if (/[{,]\s*\\*["']/.test(arg)) {
      for (const m of arg.matchAll(INLINE_JSON_PAIR)) {
        const [, name, value] = m;
        if (!JSON_SECRET_NAME.test(name) || /(?:hash(?:ed)?|digest|ttl|expir|type|mode|url|uri|file|path|id)$/i.test(name)) continue;
        const known = knownToken(value);
        if (known) add(i, known.token, `${known.name} in inline JSON "${name}"`);
        else if (looksLikeSecret(value)) add(i, value, `credential in inline JSON "${name}"`);
      }
      if (out.some(o => o.location === `args[${i}]`)) continue;
    }

    // A bare token standing alone or inside a larger argument
    const known = knownToken(arg);
    if (known) add(i, known.token, known.name);
  }
  return out;
}

/** `"name": "value"` (or single quotes) inside an argument holding inline JSON. */
// (quotes may be backslash-escaped: `{\"apiKey\":\"…\"}` inside a shell string)
const INLINE_JSON_PAIR = /\\*["']([A-Za-z_][\w.-]{0,63})\\*["']\s*:\s*\\*["']([^"'\\\s]{8,})\\*["']/g;
const JSON_SECRET_NAME = /(?:token|secret|passw|passphrase|api[_-]?key|apikey|credential|private[_-]?key|auth)/i;
