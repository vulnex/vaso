/**
 * `.env` files the way python-dotenv (1.x, `dotenv.main.DotEnv.parse` +
 * `dotenv.variables`) reads them — the loader Hermes uses to put
 * `$HERMES_HOME/.env` and the administrator-managed `.env` into its process
 * environment (`hermes_cli/env_loader._load_dotenv_with_fallback`).
 *
 * Differences from VASO's generic env parser that change values:
 *  - double-quoted values decode `\n` `\t` `\"` `\\` … escapes, single-quoted
 *    ones `\'` and `\\`; quoted values may span lines;
 *  - a statement python-dotenv can't parse (`KEY="v" junk`, `A B=1`) is
 *    dropped, not half-read;
 *  - `${VAR}` / `${VAR:-default}` are expanded in every value (`$VAR` is not).
 * Unquoted values end at a `#` preceded by whitespace (`v#c` stays `v#c`).
 */

export type DotenvAssignment = [key: string, value: string | null];

const DOUBLE_ESCAPES: Record<string, string> = {
  '\\': '\\', "'": "'", '"': '"', a: '\x07', b: '\b', f: '\f', n: '\n', r: '\r', t: '\t', v: '\v',
};

/** Statements in file order (a repeated key appears twice). `null` = a bare `KEY` with no `=`. */
export function parsePythonDotenvAssignments(raw: string): DotenvAssignment[] {
  const text = raw.replace(/^﻿/, '');
  const out: DotenvAssignment[] = [];
  let i = 0;
  const n = text.length;
  const isHSpace = (c: string | undefined) => c !== undefined && /[^\S\r\n]/.test(c);
  const skipHSpace = () => { while (i < n && isHSpace(text[i])) i++; };
  const atEol = () => i >= n || text[i] === '\n' || text[i] === '\r';
  const skipRestOfLine = () => {
    while (i < n && text[i] !== '\n' && text[i] !== '\r') i++;
    if (text[i] === '\r' && text[i + 1] === '\n') i += 2;
    else if (i < n) i++;
  };

  while (i < n) {
    // _multiline_whitespace
    while (i < n && /\s/.test(text[i])) i++;
    if (i >= n) break;
    const start = i;
    const fail = () => { i = start; skipRestOfLine(); };

    // _export: `export` followed by horizontal whitespace
    const exp = /^export[^\S\r\n]+/.exec(text.slice(i, i + 64));
    if (exp) i += exp[0].length;

    // parse_key
    let key: string | null;
    if (text[i] === '#') {
      key = null;
    } else if (text[i] === "'") {
      const m = /^'([^']+)'/.exec(text.slice(i));
      if (!m) { fail(); continue; }
      key = m[1];
      i += m[0].length;
    } else {
      const m = /^[^=#\s]+/.exec(text.slice(i));
      if (!m) { fail(); continue; }
      key = m[0];
      i += m[0].length;
    }
    skipHSpace();

    let value: string | null = null;
    if (text[i] === '=') {
      i++;
      skipHSpace();
      const q = text[i];
      if (q === "'" || q === '"') {
        // '((?:\\'|[^'])*)' / "((?:\\"|[^"])*)" — an escaped quote doesn't close
        let j = i + 1;
        let closed = -1;
        let lastEscaped = -1;
        while (j < n) {
          if (text[j] === '\\' && text[j + 1] === q) { lastEscaped = j + 1; j += 2; continue; }
          if (text[j] === q) { closed = j; break; }
          j++;
        }
        // No bare closing quote: the regex backtracks to the last escaped one
        if (closed < 0) closed = lastEscaped;
        if (closed < 0) { fail(); continue; }
        const inner = text.slice(i + 1, closed);
        value = q === '"'
          ? inner.replace(/\\([\\'"abfnrtv])/g, (_, c: string) => DOUBLE_ESCAPES[c])
          : inner.replace(/\\([\\'])/g, '$1');
        i = closed + 1;
      } else if (atEol()) {
        value = '';
      } else {
        let j = i;
        while (j < n && text[j] !== '\n' && text[j] !== '\r') j++;
        value = text.slice(i, j).replace(/\s+#.*/, '').trimEnd();
        i = j;
      }
    }
    // _comment, then _end_of_line — anything else makes the statement an error
    skipHSpace();
    if (text[i] === '#') while (i < n && text[i] !== '\n' && text[i] !== '\r') i++;
    if (!atEol()) { fail(); continue; }
    if (text[i] === '\r' && text[i + 1] === '\n') i += 2;
    else if (i < n) i++;

    if (key !== null) out.push([key, value]);
  }
  return out;
}

const POSIX_VARIABLE = /\$\{([^}:]*)(?::-([^}]*))?\}/g;

/**
 * Expand `${VAR}` / `${VAR:-default}` in each value, in file order, the way
 * Hermes loads a dotenv layer with override: a variable assigned earlier in
 * the file wins, then `lookup` (the environment the file is loaded into).
 * python-dotenv takes `default` only when VAR is absent (an empty VAR stays
 * empty). A reference nothing defines expands to "" in Hermes, but the
 * daemon's own environment isn't visible to a scan, so it is kept as written.
 */
export function expandPythonDotenv(
  assignments: DotenvAssignment[],
  lookup: (name: string) => string | undefined,
): Record<string, string> {
  const resolved = new Map<string, string | null>();
  for (const [key, value] of assignments) {
    if (value === null) {
      resolved.set(key, null);
      continue;
    }
    resolved.set(key, value.replace(POSIX_VARIABLE, (whole, name: string, fallback: string | undefined) => {
      const own = resolved.get(name);
      if (own !== undefined) return own ?? '';
      const env = lookup(name);
      if (env !== undefined) return env;
      return fallback !== undefined ? fallback : whole;
    }));
  }
  const data: Record<string, string> = {};
  for (const [key, value] of resolved) if (value !== null) data[key] = value;
  return data;
}

/** Parse and expand a dotenv file as Hermes does. */
export function parsePythonDotenv(raw: string, lookup: (name: string) => string | undefined = () => undefined): Record<string, string> {
  return expandPythonDotenv(parsePythonDotenvAssignments(raw), lookup);
}
