/**
 * The argv rules the report masker (`src/reporting/serialize.ts`), MCP-003's
 * detection (`findArgSecrets`) and the probe's scrubber
 * (`probe/secret_scrub.go`) share, so a value is a credential on all three
 * sides or on none. The shared corpus is `probe/testdata/argv-verdicts.json`.
 *
 *  1. A following element is a flag, not a value, only when it is flag-shaped
 *     (`--x`, `-x`, or `--` ending the options) and its name doesn't look
 *     random: a secret may start with `-` (one base64url token in 64), so
 *     `-Xq9Zr7Lm2Pv8Kd4…` is a value while `-v`, `-pthread`, `--no-auth` are flags.
 *  2. `-p`: after a password client any stored value glued to it is the
 *     password (`mysql -pPW`, `sshpass -pPW`); a separate value is the
 *     password only after `sshpass` (`sshpass -p PW`). MySQL/MariaDB tools
 *     take the password glued or not at all: in `mysql -p app_db` the client
 *     prompts and `app_db` is the database, so a separate value there is
 *     judged like anywhere else — a password only when it looks like a
 *     credential and isn't a port, a port mapping, a version, a package spec
 *     or a lowercase word. (`psql`/`pg_dump -p` is a port.) A MySQL/MariaDB
 *     client's `--password=<v>` is its password like a glued `-p<v>`.
 *  3. `-k`: a credential when it looks random — never a URL, a host[:port]
 *     or a path.
 *  4. `redis-cli -a <pw>` is a password.
 *  5. curl's `-u`/`--user`/`--proxy-user` (separate or `--user=`): in a
 *     `user:password` value the part after the first colon is the password
 *     unless it is empty or a reference. Other commands' `-u` (`docker -u
 *     1000:1000`, `--user app:app`) is a user, not judged here.
 *  6. `MYSQL_PWD=`, `PGPASSWORD=`, `SSHPASS=`, `REDISCLI_AUTH=` (a client's
 *     password variable): the value is the password unless a reference.
 *
 *  7. Other clients' password options take any stored value: `sqlcmd`/`bcp
 *     -P`, a registry login's `-p`/`--password` (`docker login`), `smbclient
 *     -U user%<pw>`, `lftp -u user,<pw>`, the OpenLDAP tools' `-w`, the
 *     MongoDB tools' `-p`/`--password`, `htpasswd -b`'s last argument, a
 *     FreeRDP client's `/p:<pw>` (`clientPasswordHits`).
 *  8. What `echo`/`printf` pipes into `sudo -S` or a registry login's
 *     `--password-stdin` is the password (`stdinPasswordHits`).
 *
 * In a command string the words are what the shell assembles
 * (`commandSegments`): quotes around or inside a word are the shell's at any
 * depth of escaping, `-p"pass phrase"`, `'-p'"pw"`, `"-ppw"` and `-p$'pw'`
 * are each one word.
 */

import { isCredentialReference, isPathValue, isPlaceholderSecret } from '../core/patterns.js';
import { shannonEntropy } from '../analyzers/entropy.js';
import { looksRandom } from '../analyzers/secret-values.js';

/**
 * A value that a credential flag or name labels a secret: long enough and
 * random-looking. `--api-key prod` or `--token=default` name a profile, not a key.
 */
export function looksLikeCredential(value: string): boolean {
  if (value.length < 12 || /\s/.test(value)) return false;
  if (!/[A-Za-z]/.test(value) || !/[0-9]/.test(value)) return value.length >= 20 && shannonEntropy(value) > 3.5;
  return shannonEntropy(value) > 3;
}

/**
 * A value that is a reference, a placeholder, a secret manager reference, a
 * file or a profile name — never a stored secret. The same predicate as the
 * env-block path (`isCredentialReference`), so `--token op://…` and
 * `GITHUB_TOKEN: op://…` are judged alike.
 */
export function isUnstoredValue(value: string): boolean {
  const v = value.trim().replace(/^\\*['"]|\\*['"]$/g, '');
  if (v === '') return true;
  if (isPlaceholderSecret(v) || isCredentialReference(v)) return true;
  // A reference inside the value (`Bearer ${TOKEN}`, `${HOME}/key`, `$(cat f)`) holds nothing literal
  if (/\$\{[^}]+\}|\$\(|\$env:|\{env:[^}]+\}|%[A-Za-z_][A-Za-z0-9_]*%/i.test(v)) return true;
  return false;
}

const FLAG_SHAPE = /^--?[A-Za-z][A-Za-z0-9_-]*$/;

/** Rule 1: the element is the next flag (or `--`), not the previous flag's value. */
export function isFlagShaped(token: string): boolean {
  if (token === '--') return true;
  if (!FLAG_SHAPE.test(token)) return false;
  return !looksRandom(token.replace(/^--?/, ''), 12);
}

/** Clients whose `-p` is the password (rule 2). */
const PASSWORD_P_CLIENT = /^(?:mysql|mysqldump|mysqladmin|mysqlimport|mysqlshow|mysqlcheck|mysqlpump|mysqlslap|mysqlsh|mariadb(?:-[a-z]+)?|sshpass)$/;
/** The same, found as a word in command text. */
export const PASSWORD_P_CLIENT_IN_TEXT = /(?:^|[\s/"'`(;&|])(?:mysql|mysqldump|mysqladmin|mysqlimport|mysqlshow|mysqlcheck|mysqlpump|mysqlslap|mysqlsh|mariadb(?:-[a-z]+)?|sshpass)(?=$|[\s"'`;&|)])/;
/** `sshpass`, the one client whose separate `-p <value>` is the password, as a word in command text. */
export const SEPARATE_P_CLIENT_IN_TEXT = /(?:^|[\s/"'`(;&|])sshpass(?=$|[\s"'`;&|)])/;
export const REDIS_CLI_IN_TEXT = /(?:^|[\s/"'`(;&|])redis-cli(?=$|[\s"'`;&|)])/;

const basename = (token: string): string => token.replace(/^.*[/\\]/, '').replace(/\.exe$/i, '');
export const isPasswordClient = (token: string): boolean => PASSWORD_P_CLIENT.test(basename(token));
/** Rule 2: a client whose separate `-p <value>` is the password (`sshpass`). */
export const isSeparatePasswordClient = (token: string): boolean => basename(token) === 'sshpass';
export const isRedisCli = (token: string): boolean => basename(token) === 'redis-cli';

/** A port or port mapping (`8080`, `8080:80`, `127.0.0.1:8080:80`, `53/udp`). */
export const PORT_LIKE = /^\d+(?::\d+)*(?:\/(?:tcp|udp))?$|^[\d.]+:\d+(?::\d+)?$/;
/** `npx -p <package>`: a scoped or versioned package spec. */
export const PACKAGE_SPEC = /^(?:@[\w.-]+\/)?[\w.-]+@[\w.^~*<>=-]+$|^@[\w.-]+\/[\w.-]+$/;

/** Rule 2: whether a `-p` value is a password. `afterClient`: a client
 *  that takes it in this form came before — any password client for a glued
 *  value, `sshpass` for a separate one. */
export function isPasswordAfterP(value: string, afterClient: boolean): boolean {
  if (isUnstoredValue(value)) return false;
  if (afterClient) return true;
  const v = value.replace(/^\\*["']|\\*["']$/g, '');
  if (PORT_LIKE.test(v) || /^v?\d+(?:\.\d+)*$/.test(v) || PACKAGE_SPEC.test(v) || /^[a-z]+(?:[-_.][a-z]+)*$/.test(v)) return false;
  return looksLikeCredential(v);
}

/** Rule 3: whether a `-k` value is a key. */
export function isKeyAfterK(value: string): boolean {
  const v = value.replace(/^\\*["']|\\*["']$/g, '');
  if (isUnstoredValue(v)) return false;
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(v)) return false; // URL
  if (/^(?:[A-Za-z0-9-]+\.)+[A-Za-z0-9-]+(?::\d+)?$|^[A-Za-z0-9.-]+:\d+$|^\[[0-9A-Fa-f:.]+\](?::\d+)?$/.test(v)) return false; // host[:port]
  if (isPathValue(v)) return false;
  return looksRandom(v, 16);
}

/** Rule 4: `redis-cli -a <pw>`. */
export const isPasswordAfterA = (value: string): boolean => !isUnstoredValue(value);

/**
 * Rule 6: variables a client reads its password from and nothing else
 * (`MYSQL_PWD=x mysql`, `PGPASSWORD=x psql`, `SSHPASS=x sshpass -e`,
 * `REDISCLI_AUTH=x redis-cli`): any stored value is the password, however short.
 */
export const CLIENT_PASSWORD_VAR = /^(?:MYSQL_PWD|PGPASSWORD|SSHPASS|REDISCLI_AUTH)$/;

/** Rule 5: clients whose `-u`/`--user`/`--proxy-user` value is `user:password`. */
export const isUserPassClient = (token: string): boolean => /^curl$/i.test(basename(token));
export const USER_PASS_FLAGS: ReadonlySet<string> = new Set(['-u', '--user', '--proxy-user']);

/** Rule 5: the password in a `user:password` value, or undefined. */
export function userPassword(value: string): string | undefined {
  const i = value.indexOf(':');
  if (i < 0) return undefined;
  const pw = value.slice(i + 1);
  return isUnstoredValue(pw) ? undefined : pw;
}

/**
 * Rules 7 and 8 and the shell word assembly: the TypeScript twins of
 * `clientPasswordHits`, `stdinPasswordHits` and `commandSegments` in
 * `probe/argv_rules.go` (same shapes, same corpus).
 */

/** A credential inside word `tok`, characters [from, to). */
export interface ArgvHit { tok: number; from: number; to: number }

/** Rules 7 and 8: a stored value — not empty, not a reference (also one inside it: `pw$X`). */
const passwordValue = (v: string): boolean => v !== '' && !isUnstoredValue(v) && !/\$\{?[A-Za-z_]/.test(v);

/** The command a word names, by its file name, lowercased and without `.exe`. */
export const commandBase = (t: string): string => t.replace(/^.*[/\\]/, '').toLowerCase().replace(/\.exe$/, '');

/**
 * Rule 7: an option through which a client takes its password — short
 * (`-P <v>` or glued `-P<v>`) or long (`--password <v>`, `--password=<v>`).
 * With `sep` the value is `user<sep>password`: the password follows the first `sep`.
 */
interface PasswordFlag { flag: string; sep?: string }
const SMB_FLAGS: PasswordFlag[] = [{ flag: '-U', sep: '%' }, { flag: '--user', sep: '%' }, { flag: '--password' }];
const LDAP_FLAGS: PasswordFlag[] = [{ flag: '-w' }];
const MONGO_FLAGS: PasswordFlag[] = [{ flag: '-p' }, { flag: '--password' }];
/** `login`: a registry CLI's login subcommand (`docker login`, `helm registry login`). */
const CLIENT_PASSWORD_FLAGS: ReadonlyMap<string, readonly PasswordFlag[]> = new Map<string, PasswordFlag[]>([
  ['sqlcmd', [{ flag: '-P' }, { flag: '-z' }, { flag: '-Z' }]],
  ['bcp', [{ flag: '-P' }]],
  ['login', [{ flag: '-p' }, { flag: '--password' }]],
  ['lftp', [{ flag: '-u', sep: ',' }]],
  ...['smbclient', 'rpcclient', 'smbcacls', 'smbcquotas'].map((c): [string, PasswordFlag[]] => [c, SMB_FLAGS]),
  ...['ldapsearch', 'ldapadd', 'ldapmodify', 'ldapdelete', 'ldapmodrdn', 'ldapcompare', 'ldapwhoami', 'ldapexop'].map((c): [string, PasswordFlag[]] => [c, LDAP_FLAGS]),
  ['ldappasswd', [{ flag: '-w' }, { flag: '-a' }, { flag: '-s' }]],
  ...['mongo', 'mongosh', 'mongodump', 'mongorestore', 'mongoexport', 'mongoimport', 'mongostat', 'mongotop', 'mongofiles'].map((c): [string, PasswordFlag[]] => [c, MONGO_FLAGS]),
]);
/** Commands whose `login` subcommand takes `-p`/`--password`. */
const REGISTRY_CLIS = new Set(['docker', 'podman', 'nerdctl', 'buildah', 'skopeo', 'oras', 'helm']);
/** FreeRDP clients: `/p:<password>` (2.x also `/gp:<password>`). */
const RDP_CLIENTS = new Set(['xfreerdp', 'xfreerdp3', 'wlfreerdp', 'wlfreerdp3', 'sdl-freerdp', 'sdl-freerdp3', 'wfreerdp']);
/** sudo options that take a value. */
const SUDO_VALUE_OPTION = new Set(['-u', '-g', '-h', '-p', '-C', '-D', '-R', '-T', '-U', '-r', '-t']);

/** Words of the clients rules 2–8 know, in text: a cheap filter before tokenizing. */
export const ARGV_CLIENT_IN_TEXT = /mysql|mariadb|sshpass|redis-cli|curl|PGPASSWORD|MYSQL_PWD|SSHPASS|REDISCLI_AUTH|sqlcmd|bcp|login|smbc|rpcclient|lftp|ldap|mongo|htpasswd|freerdp|sudo/i;

/** Rule 7: the passwords given through a client's password options, a FreeRDP `/p:`, `htpasswd -b`. */
export function clientPasswordHits(tokens: readonly string[]): ArgvHit[] {
  const hits: ArgvHit[] = [];
  const add = (tok: number, from: number, sep?: string): void => {
    let v = tokens[tok].slice(from);
    if (sep) {
      const k = v.indexOf(sep);
      if (k < 0) return;
      from += k + 1;
      v = v.slice(k + 1);
    }
    // `--password -` reads it from stdin; a URL is the server (`mongosh -p <url>` prompts)
    if (passwordValue(v) && v !== '-' && !v.includes('://')) hits.push({ tok, from, to: tokens[tok].length });
  };
  let client = '';
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i];
    if (t === '--') break;
    if (!t.startsWith('-')) {
      const name = commandBase(t);
      if (RDP_CLIENTS.has(client) && t.startsWith('/p:')) add(i, 3);
      else if (RDP_CLIENTS.has(client) && t.startsWith('/gp:')) add(i, 4);
      else if (name === 'htpasswd') return [...hits, ...htpasswdHits(tokens, i)];
      else if (name === 'login' && REGISTRY_CLIS.has(client)) client = 'login';
      else if (CLIENT_PASSWORD_FLAGS.has(name) || REGISTRY_CLIS.has(name) || RDP_CLIENTS.has(name)) client = name;
      continue;
    }
    for (const f of CLIENT_PASSWORD_FLAGS.get(client) ?? []) {
      const long = f.flag.startsWith('--');
      if (t === f.flag) {
        if (i + 1 < tokens.length && !isFlagShaped(tokens[i + 1])) add(++i, 0, f.sep);
        break;
      }
      if (long && t.startsWith(`${f.flag}=`)) { add(i, f.flag.length + 1, f.sep); break; }
      if (!long && t.startsWith(f.flag)) { add(i, f.flag.length, f.sep); break; }
    }
  }
  return hits;
}

/** `htpasswd -b[c] file user password`, `htpasswd -nb user password`: the last argument. */
function htpasswdHits(tokens: readonly string[], at: number): ArgvHit[] {
  let batch = false;
  let noFile = false;
  const positional: number[] = [];
  for (let j = at + 1; j < tokens.length; j++) {
    const t = tokens[j];
    if (positional.length === 0 && t.length > 1 && t[0] === '-') {
      for (let k = 1; k < t.length; k++) {
        if (t[k] === 'b') batch = true;
        else if (t[k] === 'n') noFile = true;
        else if (t[k] === 'C' || t[k] === 'r') {
          // -C cost, -r rounds: the value is the next word or glued
          if (k === t.length - 1) j++;
          break;
        }
      }
      continue;
    }
    positional.push(j);
  }
  const p = positional[noFile ? 1 : 2];
  return batch && p !== undefined && passwordValue(tokens[p]) ? [{ tok: p, from: 0, to: tokens[p].length }] : [];
}

/** Rule 8: what `echo`/`printf` pipes into a command reading its password from stdin. */
export function stdinPasswordHits(tokens: readonly string[]): ArgvHit[] {
  const hits: ArgvHit[] = [];
  let start = 0;
  let prev = -1;
  for (let i = 0; i <= tokens.length; i++) {
    if (i < tokens.length && tokens[i] !== '|') continue;
    if (prev >= 0 && readsPasswordFromStdin(tokens.slice(start, i))) hits.push(...echoedText(tokens, prev, start - 1));
    prev = start;
    start = i + 1;
  }
  return hits;
}

function echoedText(tokens: readonly string[], from: number, to: number): ArgvHit[] {
  if (from >= to) return [];
  let k = from + 1;
  const name = commandBase(tokens[from]);
  if (name === 'echo') {
    while (k < to && /^-[neE]+$/.test(tokens[k])) k++;
  } else if (name === 'printf') {
    if (k < to && tokens[k] === '--') k++;
    // `printf '%s\n' pw` prints its arguments; `printf 'pw\n'` its format
    if (k < to && tokens[k].includes('%')) k++;
  } else return [];
  const hits: ArgvHit[] = [];
  for (; k < to; k++) if (passwordValue(tokens[k])) hits.push({ tok: k, from: 0, to: tokens[k].length });
  return hits;
}

/** `sudo -S`/`--stdin`; a registry login with `--password-stdin` or `--password -`. */
function readsPasswordFromStdin(tokens: readonly string[]): boolean {
  let client = '';
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i];
    const name = commandBase(t);
    if (name === 'sudo' && client === '') {
      client = name;
      for (let j = i + 1; j < tokens.length && tokens[j].startsWith('-') && tokens[j] !== '--'; j++) {
        const o = tokens[j];
        if (o === '--stdin' || (!o.startsWith('--') && o.includes('S') && FLAG_SHAPE.test(o))) return true;
        if (SUDO_VALUE_OPTION.has(o)) j++;
      }
      continue;
    }
    if (REGISTRY_CLIS.has(name) && (client === '' || client === 'sudo')) client = name;
    else if (name === 'login' && REGISTRY_CLIS.has(client)) client = 'login';
    else if (client === 'login' && (t === '--password-stdin' || t === '--password=-' || ((t === '--password' || t === '-p') && tokens[i + 1] === '-'))) return true;
  }
  return false;
}

/** Rules 7 and 8 over a word list (a pipeline's commands separated by `|`), overlapping hits dropped. */
export function clientAndStdinHits(tokens: readonly string[]): ArgvHit[] {
  const hits: ArgvHit[] = [];
  let start = 0;
  for (let i = 0; i <= tokens.length; i++) {
    if (i < tokens.length && tokens[i] !== '|') continue;
    for (const h of clientPasswordHits(tokens.slice(start, i))) hits.push({ ...h, tok: h.tok + start });
    start = i + 1;
  }
  hits.push(...stdinPasswordHits(tokens));
  return hits.filter((h, n) => !hits.slice(0, n).some((o) => o.tok === h.tok && h.from < o.to && o.from < h.to));
}

/**
 * One word of a command line as the shell assembles it (`commandToken` in
 * the probe): quotes around and inside it left out at any depth of escaping,
 * a quoted part spanning spaces kept whole, `$'…'` decoded. `word[i]` is
 * written at `line.slice(pos[i], ends[i])`.
 */
export interface CommandToken { word: string; pos: number[]; ends: number[] }
/** One command of a line; `pipe`: its output is piped into the next. */
export interface CommandSegment { tokens: CommandToken[]; pipe: boolean }

const isQuote = (c: string): boolean => c === "'" || c === '"' || c === '`';
const SEPARATORS = new Set([';', '&&', '||', '|', '&']);
const LEAD = "'\"`([{,\\";
const TRAIL = "'\"`)]},;\\";

function escapesBefore(line: string, p: number): number {
  let k = 0;
  while (p - k > 0 && line[p - k - 1] === '\\') k++;
  return k;
}
const sameQuote = (line: string, p: number, q: number): boolean => line[p] === line[q] && escapesBefore(line, p) === escapesBefore(line, q);

/** Each quote → the next quote of the same character escaped as deeply (its closing quote). */
function closingQuotes(line: string): Map<number, number> {
  const next = new Map<number, number>();
  const last = new Map<string, number>();
  for (let p = line.length - 1; p >= 0; p--) {
    if (!isQuote(line[p])) continue;
    const kind = `${line[p]}${escapesBefore(line, p)}`;
    const q = last.get(kind);
    if (q !== undefined) next.set(p, q);
    last.set(kind, p);
  }
  return next;
}

function pairQuotes(line: string, from: number, to: number, open: number): number {
  for (let p = from; p < to; p++) {
    if (!isQuote(line[p])) continue;
    if (open < 0) open = p;
    else if (sameQuote(line, p, open)) open = -1;
  }
  return open;
}

/** `w` ends with a bracket closing one opened in it (`${PASSWORD}`, `$(cat f)`): part of the word. */
function closesInside(w: string): boolean {
  const open = ({ '}': '{', ')': '(', ']': '[' } as Record<string, string>)[w[w.length - 1]];
  return open !== undefined && w.split(open).length >= w.split(w[w.length - 1]).length;
}

function wordAfter(line: string, from: number, to: number): boolean {
  for (let p = from; p < to; p++) if (!TRAIL.includes(line[p])) return true;
  return false;
}

const ANSI_C: Record<string, string> = { a: '\x07', b: '\b', e: '\x1b', E: '\x1b', f: '\f', n: '\n', r: '\r', t: '\t', v: '\v', '\\': '\\', "'": "'", '"': '"', '?': '?' };
function ansiEscape(s: string): [string, number] {
  if (s[0] in ANSI_C) return [ANSI_C[s[0]], 1];
  const hex = /^x([0-9A-Fa-f]{1,2})/.exec(s.slice(0, 3));
  if (hex) return [String.fromCharCode(parseInt(hex[1], 16)), hex[0].length];
  const oct = /^[0-7]{1,3}/.exec(s.slice(0, 3));
  if (oct) return [String.fromCharCode(parseInt(oct[0], 8) & 0xff), oct[0].length];
  return [`\\${s[0]}`, 1];
}

/**
 * `line[j]` is the `$` of `$'…'` or `$"…"` — the latter also with its quote
 * escaped (`sshpass -p $\"pw\"` in a JSON string): the index of that quote,
 * else 0. probe/argv_rules.go dollarQuote.
 */
function dollarQuote(line: string, j: number, to: number): number {
  if (line[j] !== '$' || j + 1 >= to) return 0;
  if (line[j + 1] === "'") return j + 1;
  let k = j + 1;
  while (k < to && line[k] === '\\') k++;
  return k < to && line[k] === '"' ? k : 0;
}

/** `line.slice(from, to)` without its quotes and the backslashes escaping them; `$'…'` decoded. */
function quotesLeftOut(line: string, from: number, to: number): CommandToken {
  let word = '';
  const pos: number[] = [];
  const ends: number[] = [];
  let ansi = false;
  for (let j = from; j < to; j++) {
    const ch = line[j];
    if (ansi && ch === '\\' && j + 1 < to) {
      const [text, n] = ansiEscape(line.slice(j + 1, to));
      for (const c of text) { word += c; pos.push(j); ends.push(j + 1 + n); }
      j += n;
      continue;
    }
    if (ansi && ch === "'") { ansi = false; continue; }
    if (!ansi) {
      const q = dollarQuote(line, j, to);
      // $\"…\" in a JSON string: its quote's backslashes go too
      if (q > 0) { ansi = line[q] === "'"; j = q; continue; }
      if (isQuote(ch)) continue;
      if (ch === '\\') {
        let k = j;
        while (k < to && line[k] === '\\') k++;
        if (k < to && isQuote(line[k])) { j = k - 1; continue; }
      }
    }
    word += ch;
    pos.push(j);
    ends.push(j + 1);
  }
  return { word, pos, ends };
}

/** The commands of a line, word by word (`commandSegments` in the probe, whose comments give the rules). */
export function commandSegments(line: string): CommandSegment[] {
  const segs: CommandSegment[] = [];
  let cur: CommandToken[] = [];
  const flush = (): void => { if (cur.length > 0) segs.push({ tokens: cur, pipe: false }); cur = []; };
  const closing = /['"`]/.test(line) ? closingQuotes(line) : new Map<number, number>();
  const space = (c: string): boolean => c === ' ' || c === '\t' || c === '\n' || c === '\r';
  const chunkEnd = (i: number): number => { while (i < line.length && !space(line[i])) i++; return i; };
  // the quote open before the word (a JSON or YAML string the command is written in), read up to scanned
  let outer = -1;
  let scanned = 0;
  for (let i = 0; i < line.length;) {
    while (i < line.length && space(line[i])) i++;
    const start = i;
    i = chunkEnd(i);
    if (start === i) break;
    outer = pairQuotes(line, scanned, start, outer);
    scanned = start;
    let from = start;
    let begin = false;
    while (from < i) {
      const ch = line[from];
      const ansiC = dollarQuote(line, from, i) > 0;
      if (!ansiC && !LEAD.includes(ch)) break;
      begin = begin || isQuote(ch);
      from++;
    }
    // a quote opened inside the word: the word runs to its closing quote
    let open = pairQuotes(line, start, i, -1);
    // the last word of a string the command is written in: its last quote
    // (before closing brackets: `["-c", "… -P 'pw'"]`) closes that string,
    // not one of the word's
    let outerEnd = -1;
    if (open >= 0 && outer >= 0 && sameQuote(line, open, outer) && /^[)\]},;]*$/.test(line.slice(open + 1, i))
      && pairQuotes(line, start, open, -1) < 0) {
      outerEnd = open;
      open = -1;
    }
    while (open >= from && wordAfter(line, open + 1, i)) {
      const c = closing.get(open);
      if (c === undefined) break;
      const scanned = i;
      i = chunkEnd(c + 1);
      open = pairQuotes(line, scanned, i, open);
    }
    let to = i;
    let end = false;
    let semicolon = false;
    while (to > from && TRAIL.includes(line[to - 1]) && !closesInside(line.slice(from, to))) {
      end = end || isQuote(line[to - 1]);
      semicolon = semicolon || line[to - 1] === ';';
      to--;
    }
    const balanced = open < 0;
    // punctuation after the string's closing quote is the string's, not the word's
    const structural = /[([{,]/.test(line.slice(start, from)) || /[)\]},]/.test(line.slice(to, outerEnd >= to ? outerEnd : i));
    const prevFlag = cur.length > 0 && isFlagShaped(cur[cur.length - 1].word);
    const argument = begin && balanced && prevFlag;
    const single = begin && balanced && !structural;
    if (begin && !argument && !single) {
      const c = closing.get(open);
      if (c !== undefined && !balanced && open < from && prevFlag) {
        const inner = c - escapesBefore(line, c);
        if (inner > open + 1) cur.push(quotesLeftOut(line, open + 1, inner));
      }
      flush();
    }
    const tok = quotesLeftOut(line, from, to);
    if (SEPARATORS.has(tok.word)) {
      flush();
      if (tok.word === '|' && segs.length > 0) segs[segs.length - 1].pipe = true;
      continue;
    }
    if (tok.word !== '') cur.push(tok);
    // the string the command is written in ends with this word: so does the command
    if (semicolon || outerEnd >= 0 || (end && !argument && !single && !(balanced && !begin))) flush();
  }
  flush();
  return segs;
}

/** A line's pipelines: the words of each, its commands separated by a `|` token (`commandPipelines` in the probe). */
export function commandPipelines(line: string): CommandToken[][] {
  const out: CommandToken[][] = [];
  let cur: CommandToken[] = [];
  for (const seg of commandSegments(line)) {
    for (const t of seg.tokens) cur.push(t);
    if (seg.pipe) { cur.push({ word: '|', pos: [], ends: [] }); continue; }
    out.push(cur);
    cur = [];
  }
  if (cur.length > 0) out.push(cur);
  return out;
}

/** A request-header option (curl/wget `-H`, `--header`, `--proxy-header`) and the separator before its value word (probe headerFlag). */
const HEADER_FLAG = /(?:^|[\s"'[,(\\])(?:-H|--header|--proxy-header)(?:[ \t]+|=)/g;
/** A header whose value is a credential (probe secretHeader). */
const SECRET_HEADER_WORD = /^(?:(?:proxy-)?authorization|x-[A-Za-z0-9_-]*(?:key|token|secret|auth)[A-Za-z0-9_-]*|api[_-]?key|[A-Za-z0-9_-]*-(?:key|token|secret))$/i;
const HEADER_LINE_NAME = /^[A-Za-z][A-Za-z0-9-]*:/;
const HEADER_AUTH_SCHEME = /^\s*(?:bearer|basic|token)\s+/i;

/**
 * The shell word starting at `line[from]` as the shell assembles it: a
 * backslash-escaped space (`Authorization:\ Bearer\ <v>`, the backslash
 * doubled in a JSON string) stays in it, adjacent quoted pieces join
 * (`'Authorization: Bearer '<v>`), `$'…'` is decoded. A quote escaped as
 * deeply as `outer` (the open quote of the string the command is written
 * in; -1: none) ends the word. probe/argv_rules.go headerWordAt.
 */
function headerWordAt(line: string, from: number, outer: number): CommandToken {
  let word = '';
  const pos: number[] = [];
  const ends: number[] = [];
  const add = (ch: string, p: number, e: number): void => { word += ch; pos.push(p); ends.push(e); };
  let open = -1;
  let ansi = false;
  let j = from;
  while (j < line.length && line[j] !== '\n' && line[j] !== '\r') {
    let k = j;
    while (k < line.length && line[k] === '\\') k++;
    if (open >= 0) {
      if (k < line.length && sameQuote(line, k, open)) { open = -1; ansi = false; j = k + 1; }
      else if (ansi && k > j && k < line.length) {
        const [text, n] = ansiEscape(line.slice(k));
        for (const c of text) add(c, j, k + n);
        j = k + n;
      } else { add(line[j], j, j + 1); j++; }
      continue;
    }
    const ch = line[j];
    if (k > j && k < line.length && (line[k] === ' ' || line[k] === '\t')) { add(line[k], k, k + 1); j = k + 1; continue; }
    if (k < line.length && isQuote(line[k]) && outer >= 0 && sameQuote(line, k, outer)) break;
    if (k < line.length && isQuote(line[k])) { open = k; j = k + 1; continue; }
    const q = dollarQuote(line, j, line.length);
    if (q > 0) {
      if (outer >= 0 && sameQuote(line, q, outer)) break;
      open = q; ansi = line[q] === "'"; j = q + 1;
      continue;
    }
    if (ch === ' ' || ch === '\t' || ';|&<>'.includes(ch)) break;
    add(ch, j, j + 1);
    j++;
  }
  return { word, pos, ends };
}

/**
 * The credential-looking value of each request-header option in `line`
 * (`curl -H 'X-Api-Key: <v>'`, `-H Authorization:\ Bearer\ '<v>'`): the
 * word assembled first, then split at the header's colon and scheme.
 * `from`/`to` are where the value is written. `judge` decides which values
 * count. probe/argv_rules.go headerWordCredentials.
 */
export function headerWordValues(line: string, judge: (value: string) => boolean): Array<{ value: string; from: number; to: number }> {
  if (!/-H|--header|--proxy-header/.test(line)) return [];
  const out: Array<{ value: string; from: number; to: number }> = [];
  let scanned = 0;
  let outer = -1;
  for (const m of line.matchAll(HEADER_FLAG)) {
    const at = m.index + m[0].length;
    outer = pairQuotes(line, scanned, at, outer);
    scanned = at;
    const t = headerWordAt(line, at, outer);
    const h = HEADER_LINE_NAME.exec(t.word)?.[0];
    if (!h || !SECRET_HEADER_WORD.test(h.slice(0, -1))) continue;
    let from = h.length;
    while (from < t.word.length && (t.word[from] === ' ' || t.word[from] === '\t')) from++;
    from += HEADER_AUTH_SCHEME.exec(t.word.slice(from))?.[0].length ?? 0;
    const value = t.word.slice(from);
    if (value !== '' && judge(value)) out.push({ value, from: t.pos[from], to: t.ends[t.word.length - 1] });
  }
  return out;
}
