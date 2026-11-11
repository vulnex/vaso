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
 *  2. `-p`: after a password client (MySQL/MariaDB tools, `sshpass`) any
 *     stored value is the password, separate or glued. Elsewhere it is one
 *     only when it looks like a credential and isn't a port, a port mapping,
 *     a version, a package spec or a lowercase word. (`psql`/`pg_dump -p`
 *     is a port.)
 *  3. `-k`: a credential when it looks random — never a URL, a host[:port]
 *     or a path.
 *  4. `redis-cli -a <pw>` is a password.
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
export const REDIS_CLI_IN_TEXT = /(?:^|[\s/"'`(;&|])redis-cli(?=$|[\s"'`;&|)])/;

const basename = (token: string): string => token.replace(/^.*[/\\]/, '').replace(/\.exe$/i, '');
export const isPasswordClient = (token: string): boolean => PASSWORD_P_CLIENT.test(basename(token));
export const isRedisCli = (token: string): boolean => basename(token) === 'redis-cli';

/** A port or port mapping (`8080`, `8080:80`, `127.0.0.1:8080:80`, `53/udp`). */
export const PORT_LIKE = /^\d+(?::\d+)*(?:\/(?:tcp|udp))?$|^[\d.]+:\d+(?::\d+)?$/;
/** `npx -p <package>`: a scoped or versioned package spec. */
export const PACKAGE_SPEC = /^(?:@[\w.-]+\/)?[\w.-]+@[\w.^~*<>=-]+$|^@[\w.-]+\/[\w.-]+$/;

/** Rule 2: whether a `-p` value (separate or glued) is a password. */
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
