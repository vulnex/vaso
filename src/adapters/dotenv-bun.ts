/**
 * `.env` files the way Bun (1.3.11, the release Lyrie pins) auto-loads them
 * into `process.env` — observed by running that release against sample files:
 *  - an unquoted value ends at the first `#` (`v#c` → `v`) and is trimmed;
 *  - a value opened by `"`, `'` or `` ` `` closes at the first matching quote
 *    followed only by blanks, a `#` comment or the end of the line — it may
 *    span lines; with no such quote the line is read unquoted (quotes kept);
 *    double quotes turn `\n` into a newline, other backslashes stay;
 *  - `$VAR`, `${VAR}` and `${VAR:-default}` expand in every value (`\$` is a
 *    literal `$`) against the final environment: the process environment
 *    first, then the merged layers — so a later layer's value is seen by an
 *    earlier file's reference;
 *  - a bare `KEY` with no `=` sets nothing.
 */

/** One file's assignments, values still unexpanded (`\$` escapes kept). */
export function parseBunDotenvRaw(raw: string): Record<string, string> {
  const text = raw.replace(/^﻿/, '').replace(/\r\n?/g, '\n');
  const data: Record<string, string> = {};
  let i = 0;
  const n = text.length;
  const lineEnd = (from: number) => { const e = text.indexOf('\n', from); return e < 0 ? n : e; };

  while (i < n) {
    const end = lineEnd(i);
    const line = text.slice(i, end);
    const eq = line.indexOf('=');
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#') || eq < 0) {
      i = end + 1;
      continue;
    }
    const key = line.slice(0, eq).trim().replace(/^export\s+/, '');
    let j = i + eq + 1;
    while (j < end && (text[j] === ' ' || text[j] === '\t')) j++;
    const q = text[j];
    let value: string | undefined;
    let next = end + 1;
    if (q === '"' || q === "'" || q === '`') {
      // The first matching quote with only blanks / a comment after it on its line
      for (let k = text.indexOf(q, j + 1); k >= 0; k = text.indexOf(q, k + 1)) {
        const after = text.slice(k + 1, lineEnd(k + 1));
        if (/^[ \t]*(?:#.*)?$/.test(after)) {
          value = text.slice(j + 1, k);
          if (q === '"') value = value.replace(/\\n/g, '\n');
          next = lineEnd(k + 1) + 1;
          break;
        }
      }
    }
    if (value === undefined) value = text.slice(j, end).replace(/#.*$/, '').trim();
    if (key) data[key] = value;
    i = next;
  }
  return data;
}

const REFERENCE = /\\\$|\$\{([^}:]*)(?::-([^}]*))?(?:\}|$)|\$([A-Za-z0-9_]+)/g;

/**
 * Expand the references in `layers` (lowest precedence first). A reference
 * neither the files nor `lookup` define expands to "" in Bun; the daemon's
 * environment isn't visible to a scan, so it is kept as written.
 */
export function expandBunDotenvLayers(
  layers: Array<Record<string, string>>,
  lookup: (name: string) => string | undefined,
): Array<Record<string, string>> {
  const merged: Record<string, string> = Object.assign({}, ...layers);
  const cache = new Map<string, string>();
  const resolving = new Set<string>();
  const expand = (value: string): string => value.replace(REFERENCE, (whole, braced?: string, fallback?: string, bare?: string) => {
    if (whole === '\\$') return '$';
    const name = braced ?? bare!;
    const env = lookup(name);
    if (env !== undefined) return env;
    if (Object.hasOwn(merged, name) && !resolving.has(name)) return resolve(name);
    return fallback !== undefined ? fallback : whole;
  });
  const resolve = (name: string): string => {
    const hit = cache.get(name);
    if (hit !== undefined) return hit;
    resolving.add(name);
    const v = expand(merged[name]);
    resolving.delete(name);
    cache.set(name, v);
    return v;
  };
  return layers.map(layer => Object.fromEntries(Object.entries(layer).map(([k, v]) => {
    // A value referring to its own key sees no other definition of it
    resolving.add(k);
    const expanded = expand(v);
    resolving.delete(k);
    return [k, expanded];
  })));
}
