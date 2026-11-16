import { readRegularFile, writeRegularFile, chmodNoFollow, regularMode, UnsafeTargetError } from './safe-file.js';
import YAML from 'yaml';
import { parse as parseTOMLStrict, stringify as stringifyTOML } from 'smol-toml';
import type { FixResult, ParsedConfig } from '../core/types.js';
import { getNestedValue, keySegments, setNestedValue, type KeyPath } from '../core/utils.js';
import { loadConfig } from '../core/config-loader.js';
import { parseJsonLenient } from '../core/jsonc.js';
import { scrubParseError } from '../core/parse-error.js';
import { editJsonText } from './json-edit.js';
import { isDeepStrictEqual } from 'node:util';
import { AsyncLocalStorage } from 'node:async_hooks';

/**
 * Update or insert a key=value pair in a .env file.
 * Preserves comments and line ordering. The line rewritten is the one the
 * loader reads (parseEnv in config-loader, like dotenv): the last assignment
 * of the key, `export KEY=…` included (the `export` is kept).
 */
export async function updateEnvFile(filePath: string, key: string, value: string): Promise<void> {
  const raw = (await readRegularFile(filePath)).toString('utf-8');
  // A byte-order mark and CRLF line endings are kept: the edited and the
  // inserted lines end like the rest of the file
  const bom = raw.startsWith('﻿') ? '﻿' : '';
  const content = raw.slice(bom.length);
  const crlf = content.includes('\r\n');
  const lines = content.split('\n');
  let found = false;

  for (let i = lines.length - 1; i >= 0; i--) {
    const trimmed = lines[i].trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const eqIndex = trimmed.indexOf('=');
    if (eqIndex === -1) continue;
    const rawKey = trimmed.slice(0, eqIndex).trim();
    const exported = /^export\s+/.test(rawKey);
    if (rawKey.replace(/^export\s+/, '') === key) {
      const cr = lines[i].endsWith('\r') ? '\r' : '';
      // a trailing comment after the value stays on the line
      const comment = /^\s*(?:"(?:[^"\\]|\\.)*"|'[^']*'|[^\s#]*)(\s+#.*)$/.exec(trimmed.slice(eqIndex + 1))?.[1] ?? '';
      lines[i] = `${exported ? 'export ' : ''}${key}=${value}${comment}${cr}`;
      found = true;
      break;
    }
  }

  if (!found) {
    // Insert before trailing blank lines
    let insertIndex = lines.length;
    while (insertIndex > 0 && lines[insertIndex - 1].trim() === '') {
      insertIndex--;
    }
    // After a last line without a newline, that line gets one first
    if (insertIndex === lines.length && insertIndex > 0) {
      if (crlf) lines[insertIndex - 1] += '\r';
      lines.push('');
    }
    lines.splice(insertIndex, 0, `${key}=${value}${crlf ? '\r' : ''}`);
  }

  await writeRegularFile(filePath, bom + lines.join('\n'));
}

/**
 * Update a nested value in a JSON file. The key's value is edited in the text
 * (see json-edit.ts), so JSONC/JSON5 comments, number spellings and integers
 * beyond 2^53 survive; the result must parse to the intended document.
 * Layouts the editor can't follow are re-serialized as plain JSON (which both
 * JSONC and JSON5 accept), with the detected indentation.
 */
export async function updateJsonFile(filePath: string, keyPath: KeyPath, value: unknown): Promise<void> {
  const content = (await readRegularFile(filePath)).toString('utf-8');
  // JSONC/JSON5 configs load (see config-loader) — the fix must read them too.
  const obj = parseJsonLenient(content.replace(/^\uFEFF/, '')) as Record<string, unknown>;
  setNestedValue(obj, keyPath, value);

  const edited = editJsonText(content, keySegments(keyPath), value);
  if (edited !== undefined) {
    try {
      if (isDeepStrictEqual(parseJsonLenient(edited.replace(/^\uFEFF/, '')), obj)) {
        await writeRegularFile(filePath, edited);
        return;
      }
    } catch {
      // the in-place edit doesn't parse — fall back below
    }
  }

  // Detect indentation from the file
  const indentMatch = content.match(/^(\s+)/m);
  const indent = indentMatch ? indentMatch[1].length : 2;
  await writeRegularFile(filePath, JSON.stringify(obj, null, indent) + '\n');
}

/**
 * Notes a write leaves for the person running `vaso fix` — a layout the
 * writer could not keep. The fix engine prints them under the fix's line.
 */
const writeNotes = new AsyncLocalStorage<string[]>();

/** Run `fn` collecting the notes the config writers leave. */
export async function collectWriteNotes<T>(fn: () => Promise<T>): Promise<{ value: T; notes: string[] }> {
  const notes: string[] = [];
  const value = await writeNotes.run(notes, fn);
  return { value, notes };
}

function noteWrite(note: string): void {
  writeNotes.getStore()?.push(note);
}

/**
 * Update a nested value in a YAML file using Document API to preserve comments and structure.
 * Integers are read as BigInt so values beyond 2^53 are written back unchanged.
 * An existing scalar is edited in its source token and a missing key is
 * inserted as new lines in its block mapping, so the rest of the file —
 * folding, flow spacing, quoting, comments — stays byte for byte. Only when
 * neither is possible is the document re-serialized (and a note says so).
 */
export async function updateYamlFile(filePath: string, keyPath: KeyPath, value: unknown): Promise<void> {
  const content = (await readRegularFile(filePath)).toString('utf-8');
  const doc = YAML.parseDocument(content, { intAsBigInt: true });
  const keys = keySegments(keyPath);
  if (doc.errors.length > 0) {
    throw new Error(`${filePath} has YAML errors (${doc.errors[0].code === 'DUPLICATE_KEY' ? 'a duplicate key' : 'it does not parse cleanly'}) — vaso won't rewrite it; set ${keys.join('.')} by hand`);
  }
  assertNoAliasOnPath(doc, keys, filePath);
  try {
    doc.setIn(keys, value);
  } catch {
    throw new Error(yamlPathBlocked(doc, keys, filePath));
  }
  // what the re-serialized document reads back as (a number written reads back as BigInt)
  const expected = YAML.parseDocument(doc.toString(), { intAsBigInt: true }).toJS();
  const edited = editYamlScalar(content, keys, value, expected) ?? insertYamlKey(content, keys, value, expected);
  if (edited === undefined) {
    noteWrite(`${filePath} was re-serialized to set ${keys.join('.')} (its layout didn't allow an in-place edit): values and comments are kept, spacing and line folding may differ`);
  }
  await writeRegularFile(filePath, edited ?? doc.toString({ lineWidth: 0, flowCollectionPadding: false }));
}

/**
 * Why `setIn` couldn't place `keys` — in plain words instead of the yaml
 * library's ("Expected YAML collection at gateway. Remaining path: tls,enabled"):
 * the first parent on the path that isn't a mapping, and what it is instead.
 */
export function yamlPathBlocked(doc: YAML.Document, keys: string[], filePath: string): string {
  const leaf = keys.join('.');
  for (let i = 1; i < keys.length; i++) {
    const node = doc.getIn(keys.slice(0, i), true);
    if (node === undefined || YAML.isMap(node)) continue;
    const what = YAML.isSeq(node) ? 'a list'
      : YAML.isScalar(node) && (node.value === null || node.value === undefined) ? 'empty (null)'
      : 'a single value';
    return `${keys.slice(0, i).join('.')} in ${filePath} is ${what}, not a mapping — there is nowhere to set ${keys.slice(i).join('.')} under it; set ${leaf} by hand`;
  }
  if (!YAML.isMap(doc.contents) && doc.contents !== null) {
    return `${filePath} is not a mapping at the top level — set ${leaf} by hand`;
  }
  return `${leaf} could not be set in ${filePath} — set it by hand`;
}

/**
 * Refuse a key path that runs through (or ends at) a YAML alias, or through a
 * node carrying an anchor that an alias elsewhere refers to: the value lives
 * at the anchor, and changing it there would change every other place that
 * shares it. A merge key (`<<: *defaults`) is fine when the merged key is the
 * leaf — a key set next to it overrides the merged one — but not when a
 * mapping on the path exists only through the merge: merging is shallow, so
 * a new `tls:` next to `<<` would replace the merged `tls` and drop its
 * other keys.
 */
function assertNoAliasOnPath(doc: YAML.Document, keys: string[], filePath: string): void {
  // the nodes aliases actually refer to (an anchor name defined twice refers to the latest definition before the alias)
  const aliased = new Set<unknown>();
  YAML.visit(doc, { Alias: (_k, a) => { aliased.add(a.resolve(doc)); } });
  const refuse = (i: number, what: string): never => {
    const at = keys.slice(0, i).join('.') || '(document root)';
    throw new Error(`${at} in ${filePath} is ${what} — vaso won't change the anchored value it shares with other keys; set ${keys.join('.')} by hand`);
  };
  let node: unknown = doc.contents;
  for (let i = 0; i <= keys.length; i++) {
    if (YAML.isAlias(node)) refuse(i, `a YAML alias (*${node.source})`);
    if (YAML.isNode(node) && node.anchor && aliased.has(node)) refuse(i, `a YAML anchor (&${node.anchor}) other keys alias`);
    if (i === keys.length || !(YAML.isMap(node) || YAML.isSeq(node))) return;
    if (YAML.isMap(node) && i < keys.length - 1 && !node.has(keys[i]) && mergedHas(doc, node, keys[i], new Set())) {
      const at = keys.slice(0, i + 1).join('.');
      throw new Error(`${at} in ${filePath} comes from a YAML merge key (<<) — setting ${keys.join('.')} there would replace the merged mapping and drop its other keys; set it by hand`);
    }
    node = node.get(keys[i], true);
  }
}

/** Whether `key` reaches `map` through one of its `<<` merge keys. */
function mergedHas(doc: YAML.Document, map: YAML.YAMLMap, key: string, seen: Set<unknown>): boolean {
  if (seen.has(map)) return false;
  seen.add(map);
  for (const item of map.items) {
    if (!YAML.isScalar(item.key) || item.key.value !== '<<') continue;
    const sources = YAML.isSeq(item.value) ? item.value.items : [item.value];
    for (const source of sources) {
      const target = YAML.isAlias(source) ? source.resolve(doc) : source;
      if (YAML.isMap(target) && (target.has(key) || mergedHas(doc, target, key, seen))) return true;
    }
  }
  return false;
}

/**
 * Add a missing key as new lines at the end of the deepest existing block
 * mapping on its path, indented like that mapping's keys (or as one more pair
 * of a flow mapping `{…}`); undefined when that isn't possible (a non-mapping
 * on the path, several documents) or the result doesn't parse to `expected`.
 */
function insertYamlKey(content: string, keys: string[], value: unknown, expected: unknown): string | undefined {
  try {
    const docs = YAML.parseAllDocuments(content, { intAsBigInt: true });
    if (!Array.isArray(docs) || docs.length !== 1 || docs[0].errors.length > 0) return undefined;
    let map: unknown = docs[0].contents;
    let depth = 0;
    while (depth < keys.length && YAML.isMap(map) && map.has(keys[depth])) {
      map = map.get(keys[depth], true);
      depth++;
    }
    if (depth === keys.length || !YAML.isMap(map) || map.items.length === 0) return undefined;
    const first = map.items[0].key;
    const last = map.items[map.items.length - 1];
    const lastEnd = (YAML.isNode(last.value) ? last.value.range?.[1] : undefined) ?? (YAML.isNode(last.key) ? last.key.range?.[1] : undefined);
    if (!YAML.isNode(first) || !first.range || lastEnd === undefined) return undefined;
    let sub: unknown = value;
    for (let i = keys.length - 1; i > depth; i--) sub = { [keys[i]]: sub };
    const check = (out: string) => (isDeepStrictEqual(YAML.parseDocument(out, { intAsBigInt: true }).toJS(), expected) ? out : undefined);
    if (map.flow) {
      // `{a: 1}` → `{a: 1, key: value}`, the new pair in flow style after the last one
      const flow = { collectionStyle: 'flow', flowCollectionPadding: false, lineWidth: 0 } as const;
      const pair = `${YAML.stringify(keys[depth], flow).trim()}: ${YAML.stringify(sub, flow).trim()}`;
      if (pair.includes('\n')) return undefined;
      return check(`${content.slice(0, lastEnd)}, ${pair}${content.slice(lastEnd)}`);
    }
    const lineStart = content.lastIndexOf('\n', first.range[0] - 1) + 1;
    const indent = content.slice(lineStart, first.range[0]).replace(/^\uFEFF/, '');
    if (!/^ *$/.test(indent)) return undefined; // a key not at the start of its line (`- key:` in a sequence)
    // after the line the last entry ends on (its trailing comment included)
    const eol = content.includes('\r\n') ? '\r\n' : '\n';
    let at: number;
    let prefix = '';
    if (lastEnd > 0 && content[lastEnd - 1] === '\n') {
      at = lastEnd;
    } else {
      const nl = content.indexOf('\n', lastEnd);
      if (nl === -1) { at = content.length; prefix = eol; } else at = nl + 1;
    }
    const text = YAML.stringify({ [keys[depth]]: sub }, { lineWidth: 0, indent: indentStep(content, docs[0].contents) })
      .replace(/\n$/, '').split('\n').map(l => indent + l + eol).join('');
    return check(content.slice(0, at) + prefix + text + content.slice(at));
  } catch {
    // fall back to re-serializing the document
  }
  return undefined;
}

/** The file's indentation step: how far the first block mapping under a root key is indented; 2 when there is none. */
function indentStep(content: string, root: unknown): number {
  // a byte-order mark before the first line is not a column
  const column = (offset: number) => {
    const lineStart = content.lastIndexOf('\n', offset - 1) + 1;
    return offset - lineStart - (lineStart === 0 && content.startsWith('\uFEFF') ? 1 : 0);
  };
  if (!YAML.isMap(root) || root.flow) return 2;
  for (const item of root.items) {
    const inner = item.value;
    if (!YAML.isMap(inner) || inner.flow || !YAML.isNode(item.key) || !item.key.range) continue;
    const key = inner.items[0]?.key;
    if (!YAML.isNode(key) || !key.range) continue;
    const step = column(key.range[0]) - column(item.key.range[0]);
    if (step > 0) return step;
  }
  return 2;
}

/** Replace an existing scalar's source token; undefined when that isn't possible or doesn't parse to `expected`. */
function editYamlScalar(content: string, keys: string[], value: unknown, expected: unknown): string | undefined {
  if (value === null || !['string', 'number', 'boolean', 'bigint'].includes(typeof value)) return undefined;
  try {
    const tokens = Array.from(new YAML.Parser().parse(content));
    const docs = Array.from(new YAML.Composer({ intAsBigInt: true, keepSourceTokens: true }).compose(tokens));
    if (docs.length !== 1) return undefined;
    const node = docs[0].getIn(keys, true);
    if (!YAML.isScalar(node) || !node.srcToken) return undefined;
    const token = node.srcToken;
    const types = [undefined, 'QUOTE_DOUBLE'] as const;
    for (const type of typeof value === 'string' ? types : types.slice(0, 1)) {
      YAML.CST.setScalarValue(token, String(value), type ? { type } : undefined);
      const out = tokens.map(t => YAML.CST.stringify(t)).join('');
      if (isDeepStrictEqual(YAML.parseDocument(out, { intAsBigInt: true }).toJS(), expected)) return out;
    }
  } catch {
    // fall back to re-serializing the document
  }
  return undefined;
}

/** Split a TOML key (`a."b.c".d`) into its segments; undefined when malformed. */
function splitTomlKey(key: string): string[] | undefined {
  const out: string[] = [];
  const src = key.trim();
  let i = 0;
  while (i < src.length) {
    while (src[i] === ' ' || src[i] === '\t') i++;
    let seg: string;
    if (src[i] === '"' || src[i] === "'") {
      const q = src[i];
      let j = i + 1;
      while (j < src.length && src[j] !== q) j += q === '"' && src[j] === '\\' ? 2 : 1;
      if (j >= src.length) return undefined;
      const body = src.slice(i + 1, j);
      if (q === '"') {
        try {
          seg = JSON.parse(`"${body}"`) as string;
        } catch {
          return undefined;
        }
      } else {
        seg = body;
      }
      i = j + 1;
    } else {
      const m = /^[A-Za-z0-9_-]+/.exec(src.slice(i));
      if (!m) return undefined;
      seg = m[0];
      i += m[0].length;
    }
    out.push(seg);
    while (src[i] === ' ' || src[i] === '\t') i++;
    if (i < src.length) {
      if (src[i] !== '.') return undefined;
      i++;
    }
  }
  return out.length > 0 ? out : undefined;
}

/**
 * Index of the `]` closing a `[table]` header line — the first one outside a
 * quoted key, so a `]` in a trailing comment (`[gateway] # see [docs]`) or in
 * a quoted segment (`[a."x]y"]`) doesn't end it. -1 when there is none.
 */
function headerClose(t: string): number {
  for (let i = 1; i < t.length; i++) {
    const c = t[i];
    if (c === '"' || c === "'") {
      let j = i + 1;
      while (j < t.length && t[j] !== c) j += c === '"' && t[j] === '\\' ? 2 : 1;
      if (j >= t.length) return -1;
      i = j;
      continue;
    }
    if (c === ']') return i;
    if (c === '#') return -1;
  }
  return -1;
}

function tomlKey(segments: string[]): string {
  return segments.map(s => (/^[A-Za-z0-9_-]+$/.test(s) ? s : JSON.stringify(s))).join('.');
}

/**
 * Follow a TOML value that starts at `lines[line][from]`, across lines for
 * multi-line arrays/strings. Returns the line and column just past it (before
 * any trailing comment), or undefined when it can't be followed.
 */
function scanTomlValue(lines: string[], line: number, from: number): { line: number; end: number } | undefined {
  let depth = 0;
  let l = line;
  let i = from;
  while (l < lines.length) {
    let t = lines[l];
    let comment = false;
    while (i < t.length) {
      const c = t[i];
      const triple = t.slice(i, i + 3);
      if (triple === '"""' || triple === "'''") {
        let close = t.indexOf(triple, i + 3);
        let cur = t;
        while (close === -1 && ++l < lines.length) {
          cur = lines[l];
          close = cur.indexOf(triple);
        }
        if (close === -1) return undefined;
        t = cur;
        i = close + 3;
        while (t[i] === triple[0]) i++; // up to two extra quotes belong to the string
        continue;
      }
      if (c === '"' || c === "'") {
        let j = i + 1;
        while (j < t.length && t[j] !== c) j += c === '"' && t[j] === '\\' ? 2 : 1;
        if (j >= t.length) return undefined;
        i = j + 1;
        continue;
      }
      if (c === '#') {
        if (depth === 0) return { line: l, end: i };
        comment = true; // comment inside a multi-line array
        break;
      }
      if (c === '[' || c === '{') depth++;
      if (c === ']' || c === '}') depth--;
      i++;
    }
    if (depth === 0 && !comment) return { line: l, end: t.length };
    l++;
    i = 0;
  }
  return undefined;
}

/** Parse TOML with integers beyond 2^53 kept exact (BigInt), so they survive a re-serialization. */
function parseTOML(content: string): Record<string, unknown> {
  try {
    return parseTOMLStrict(content, { integersAsBigInt: 'asNeeded' }) as Record<string, unknown>;
  } catch (err) {
    // A fix failure prints this message: no code frame of the file
    throw scrubParseError(err);
  }
}

/** Order-insensitive structural equality for parsed TOML documents. */
function tomlEqual(a: unknown, b: unknown): boolean {
  if (a instanceof Date || b instanceof Date) return String(a) === String(b);
  if (Array.isArray(a) || Array.isArray(b)) {
    return Array.isArray(a) && Array.isArray(b) && a.length === b.length && a.every((x, i) => tomlEqual(x, b[i]));
  }
  if (a && b && typeof a === 'object' && typeof b === 'object') {
    const ra = a as Record<string, unknown>;
    const rb = b as Record<string, unknown>;
    const ka = Object.keys(ra);
    return ka.length === Object.keys(rb).length
      && ka.every(k => Object.prototype.hasOwnProperty.call(rb, k) && tomlEqual(ra[k], rb[k]));
  }
  return Object.is(a, b);
}

/**
 * Set `segs` inside a one-line inline table (`{ a = 1, b = { c = 2 } }`),
 * replacing an existing value or appending the key before the closing brace.
 */
function editInlineTable(text: string, segs: string[], literal: string): string | undefined {
  if (!text.startsWith('{') || !text.endsWith('}')) return undefined;
  const members: { key: string[]; valueStart: number; valueEnd: number }[] = [];
  let i = 1;
  while (i < text.length - 1) {
    while (text[i] === ' ' || text[i] === '\t') i++;
    if (i >= text.length - 1) break;
    const eq = text.indexOf('=', i);
    if (eq === -1) return undefined;
    const key = splitTomlKey(text.slice(i, eq));
    if (!key) return undefined;
    let j = eq + 1;
    while (text[j] === ' ' || text[j] === '\t') j++;
    const valueStart = j;
    let depth = 0;
    while (j < text.length - 1 || depth > 0) {
      const c = text[j];
      if (c === undefined) return undefined;
      if (c === '"' || c === "'") {
        let k = j + 1;
        while (k < text.length && text[k] !== c) k += c === '"' && text[k] === '\\' ? 2 : 1;
        if (k >= text.length) return undefined;
        j = k + 1;
        continue;
      }
      if (c === '[' || c === '{') depth++;
      else if (c === ']' || c === '}') depth--;
      else if (c === ',' && depth === 0) break;
      j++;
    }
    members.push({ key, valueStart, valueEnd: j - (text.slice(valueStart, j).length - text.slice(valueStart, j).trimEnd().length) });
    i = text[j] === ',' ? j + 1 : j;
  }
  for (const m of [...members].reverse()) {
    if (m.key.join('\u0000') === segs.join('\u0000')) {
      return text.slice(0, m.valueStart) + literal + text.slice(m.valueEnd);
    }
    if (m.key.length === 1 && m.key[0] === segs[0] && segs.length > 1 && text[m.valueStart] === '{') {
      const inner = editInlineTable(text.slice(m.valueStart, m.valueEnd), segs.slice(1), literal);
      return inner === undefined ? undefined : text.slice(0, m.valueStart) + inner + text.slice(m.valueEnd);
    }
  }
  const entry = `${tomlKey(segs)} = ${literal}`;
  if (members.length === 0) return `{ ${entry} }`;
  const last = members[members.length - 1];
  return `${text.slice(0, last.valueEnd)}, ${entry}${text.slice(last.valueEnd)}`;
}

/**
 * Edit one key in TOML text in place: replace the value of an existing
 * `key = …` line (keeping indentation and a trailing comment), else add the
 * key under the deepest `[table]` header on its path, else append a new
 * table. Returns undefined when the layout isn't one this can follow.
 */
function editTomlText(content: string, path: string[], value: unknown): string | undefined {
  // A CRLF file is edited as LF and written back CRLF, so the edited and the
  // inserted lines end like the rest (a mixed file keeps its bare LFs)
  const crlf = content.includes('\r\n') && !/(^|[^\r])\n/.test(content);
  if (crlf) return editTomlLines(content.replace(/\r\n/g, '\n'), path, value)?.replace(/\n/g, '\r\n');
  return editTomlLines(content, path, value);
}

function editTomlLines(content: string, path: string[], value: unknown): string | undefined {
  let rendered: string;
  try {
    rendered = stringifyTOML({ v: value }).trim();
  } catch {
    return undefined;
  }
  if (!rendered.startsWith('v = ') || rendered.includes('\n')) return undefined; // tables etc.
  const literal = rendered.slice(4);

  const SEP = '\u0000';
  const lines = content.split('\n');
  const want = path.join(SEP);
  // Last line of each table's own key/value block (root = '').
  const tables = new Map<string, { last: number }>([['', { last: -1 }]]);
  let current: string[] | undefined = [];
  for (let n = 0; n < lines.length; n++) {
    const t = lines[n].trim();
    if (!t || t.startsWith('#')) continue;
    if (t.startsWith('[[')) {
      current = undefined; // array of tables — keys there are not edited in place
      continue;
    }
    if (t.startsWith('[')) {
      const close = headerClose(t);
      current = close > 0 ? splitTomlKey(t.slice(1, close)) : undefined;
      if (current) tables.set(current.join(SEP), { last: n });
      continue;
    }
    const eq = lines[n].indexOf('=');
    if (eq === -1) return undefined;
    const keySegs = splitTomlKey(lines[n].slice(0, eq));
    const afterEq = lines[n].slice(eq + 1);
    const valueStart = eq + 1 + (afterEq.length - afterEq.trimStart().length);
    const span = scanTomlValue(lines, n, valueStart);
    if (!keySegs || !span) return undefined;
    if (current) {
      const full = [...current, ...keySegs];
      if (span.line === n && full.length < path.length && full.every((k, i) => k === path[i])
        && lines[n][valueStart] === '{') {
        // A key inside an inline table: `workspace = { a = 1, b = 2 }`
        const inline = editInlineTable(lines[n].slice(valueStart, span.end).trimEnd(), path.slice(full.length), literal);
        if (inline === undefined) return undefined;
        const tail = lines[n].slice(valueStart).slice(lines[n].slice(valueStart, span.end).trimEnd().length);
        const replaced = `${lines[n].slice(0, valueStart)}${inline}${tail}`;
        return [...lines.slice(0, n), replaced, ...lines.slice(n + 1)].join('\n');
      }
      if (full.join(SEP) === want) {
        const tail = lines[span.line].slice(span.end).trim();
        const comment = tail.startsWith('#') ? ` ${tail}` : '';
        const replaced = `${lines[n].slice(0, valueStart)}${literal}${comment}`;
        return [...lines.slice(0, n), replaced, ...lines.slice(span.line + 1)].join('\n');
      }
      const entry = tables.get(current.join(SEP));
      if (entry) entry.last = span.line;
    }
    n = span.line;
  }

  // Not present: add it under the deepest table on the path that has a header
  // (a root key goes at the end of the root block).
  for (let k = path.length - 1; k >= 0; k--) {
    if (k === 0 && path.length > 1) break; // a new [table] reads better than a root dotted key
    const entry = tables.get(path.slice(0, k).join(SEP));
    if (!entry) continue;
    const at = entry.last + 1;
    return [...lines.slice(0, at), `${tomlKey(path.slice(k))} = ${literal}`, ...lines.slice(at)].join('\n');
  }
  const body = content.replace(/\n*$/, '');
  return `${body}${body ? '\n\n' : ''}[${tomlKey(path.slice(0, -1))}]\n${tomlKey(path.slice(-1))} = ${literal}\n`;
}

/**
 * Update a nested value in a TOML file. The edit is surgical — only the one
 * key line changes, so comments, key order and number formatting (`1.0`)
 * survive — and the result is parse-validated against the intended document
 * before it is written; a key inside a one-line inline table is edited there.
 * Layouts the line editor can't follow (multi-line inline tables, arrays of
 * tables) fall back to a full smol-toml re-serialization.
 */
export async function updateTomlFile(filePath: string, keyPath: KeyPath, value: unknown): Promise<void> {
  const content = (await readRegularFile(filePath)).toString('utf-8');
  const obj = parseTOML(content) as Record<string, unknown>;
  setNestedValue(obj, keyPath, value);

  const edited = editTomlText(content, keySegments(keyPath), value);
  if (edited !== undefined) {
    try {
      if (tomlEqual(parseTOML(edited), obj)) {
        await writeRegularFile(filePath, edited);
        return;
      }
    } catch {
      // the in-place edit produced invalid TOML — fall back below
    }
  }
  const rewritten = stringifyTOML(obj) + '\n';
  parseTOML(rewritten);
  await writeRegularFile(filePath, rewritten);
}

/**
 * Set file permissions (chmod). Only effective on darwin/linux.
 */
export async function chmodFile(filePath: string, mode: number): Promise<void> {
  await chmodNoFollow(filePath, mode);
}

/**
 * Make a file owner-only by clearing its group/other bits — never by setting
 * 600, which would give a 400 file owner write. Files already owner-only are
 * left alone. Returns whether the mode changed.
 */
export async function restrictToOwner(filePath: string): Promise<boolean> {
  return (await restrictModeToOwner(filePath)) !== undefined;
}

/** restrictToOwner, saying what it changed: 'dir' / 'file', or undefined when already owner-only. */
async function restrictModeToOwner(filePath: string): Promise<'file' | 'dir' | undefined> {
  const { mode, dir } = await regularMode(filePath);
  if ((mode & 0o077) === 0) return undefined;
  await chmodNoFollow(filePath, mode & 0o7700);
  return dir ? 'dir' : 'file';
}

/** restrictToOwner over a list of files (missing ones skipped); the result of a fix(). */
export async function restrictFilesToOwner(checkId: string, paths: Iterable<string>): Promise<FixResult> {
  let files = 0;
  let dirs = 0;
  // One unsafe file (a symlink, a hard link, a path leaving the home) is
  // refused and named; the others are still fixed
  const refused: string[] = [];
  for (const path of paths) {
    try {
      const changed = await restrictModeToOwner(path);
      if (changed === 'file') files++;
      else if (changed === 'dir') dirs++;
    } catch (err) {
      if (err instanceof UnsafeTargetError) refused.push(`${err.path} ${err.reason}`);
      // a missing file is nothing to fix; any other error (EPERM: owned by
      // someone else) is reported, not swallowed
      else if ((err as NodeJS.ErrnoException).code !== 'ENOENT') refused.push(`${path}: ${(err as Error).message}`);
    }
  }
  const changed = [
    ...(files > 0 ? [`${files} file(s)`] : []),
    ...(dirs > 0 ? [`${dirs} director${dirs === 1 ? 'y' : 'ies'}`] : []),
  ];
  const parts: string[] = [];
  if (changed.length > 0) parts.push(`Removed group/other access from ${changed.join(' and ')}`);
  if (refused.length > 0) parts.push(`not changed: ${refused.join('; ')}`);
  return {
    checkId,
    applied: files + dirs > 0,
    message: parts.length > 0 ? parts.join(' — ') : 'Files are already owner-only',
    ...(files + dirs === 0 && refused.length === 0 ? { alreadyDone: true } : {}),
  };
}

/**
 * Dispatcher: route to the correct writer based on config format.
 * For env files, keyPath should be the flat env var name (e.g., 'HTTP_HOST').
 * For json/yaml/toml files, keyPath is dot-separated (e.g., 'gateway.host'),
 * or its segments when a key contains a dot (['risk_profiles', 'prod.v2']).
 */
export async function updateConfigValue(config: ParsedConfig, keyPath: KeyPath, value: unknown): Promise<void> {
  switch (config.format) {
    case 'env': {
      const segs = keySegments(keyPath);
      // a .env file is flat: a nested path has no variable to write
      if (typeof keyPath !== 'string' && segs.length !== 1) throw new Error(`Cannot write a nested key to an env file: ${keyPath.join('.')}`);
      await updateEnvFile(config.filePath, segs.join('.'), String(value));
      break;
    }
    case 'json':
      await updateJsonFile(config.filePath, keyPath, value);
      break;
    case 'yaml':
      await updateYamlFile(config.filePath, keyPath, value);
      break;
    case 'toml':
      await updateTomlFile(config.filePath, keyPath, value);
      break;
    default:
      throw new Error(`Cannot write to config format: ${config.format}`);
  }
}

/**
 * Declarative one-setting fix: what to write, expressed per config dialect.
 * `env` names the flat variable for .env files; `path` the dot-separated key
 * for json/yaml/toml. Omitting one marks that dialect as unsupported for the
 * fix, so those config files are skipped rather than written badly.
 */
export interface FixUpdateSpec {
  checkId: string;
  /** Flat variable name for env-format configs. Omit → env files are skipped. */
  env?: string;
  /** Key path for json/yaml/toml configs (segments when a key has a dot). Omit → structured files are skipped. */
  path?: KeyPath;
  /** Value to write (structured formats; env too unless envValue is given). */
  value: unknown;
  /** Env-file value override for values whose String() form is wrong (e.g. arrays as CSV). */
  envValue?: string;
  /** Success message for the FixResult. */
  message: string;
  /** Not-applied message when no compatible config file exists. */
  noConfigMessage?: string;
}

/**
 * The fix() body shared by most single-setting remediations: walk the
 * installation's config files, write the setting into the first one whose
 * format the spec covers, and report applied/not-applied. Replaces the
 * per-format if/ternary dispatch that used to be copied into every fix.
 */
/**
 * Like fixFirstConfig, but for a setting that is wrong in several files at
 * once (user + desktop config, parent + sub-agent): writes it into every
 * compatible file given, so one `vaso fix` run leaves none behind.
 */
export async function fixEveryConfig(configs: ParsedConfig[], spec: FixUpdateSpec): Promise<FixResult> {
  let fixed = 0;
  for (const config of configs) {
    const r = await fixFirstConfig([config], spec);
    if (r.applied) fixed++;
  }
  if (fixed === 0) return fixFirstConfig([], spec);
  return { checkId: spec.checkId, applied: true, message: fixed > 1 ? `${spec.message} (${fixed} files)` : spec.message };
}

/**
 * Whether the file on disk already holds the value a fix would write. Configs
 * in a fix run are the scan's snapshot: a file shared by several installs
 * (OpenClaw's openclaw.json and its sub-agents) may have been fixed a moment
 * ago — that is not another applied fix.
 */
async function alreadySet(config: ParsedConfig, spec: FixUpdateSpec): Promise<boolean> {
  try {
    const current = await loadConfig(config.filePath);
    if (config.format === 'env') {
      return spec.env !== undefined && current.data[spec.env] === (spec.envValue ?? String(spec.value));
    }
    return spec.path !== undefined && JSON.stringify(getNestedValue(current.data, spec.path)) === JSON.stringify(spec.value);
  } catch {
    return false;
  }
}

export async function fixFirstConfig(configs: ParsedConfig[], spec: FixUpdateSpec): Promise<FixResult> {
  let setIn: string | undefined;
  for (const config of configs) {
    if (await alreadySet(config, spec)) {
      setIn ??= config.filePath;
      continue;
    }
    if (config.format === 'env') {
      if (spec.env === undefined) continue;
      await updateEnvFile(config.filePath, spec.env, spec.envValue ?? String(spec.value));
    } else if (config.format === 'json' || config.format === 'yaml' || config.format === 'toml') {
      if (spec.path === undefined) continue;
      await updateConfigValue(config, spec.path, spec.value);
    } else {
      continue; // unknown format — nothing safe to write
    }
    return { checkId: spec.checkId, applied: true, message: spec.message };
  }
  if (setIn) return { checkId: spec.checkId, applied: false, alreadyDone: true, message: `${spec.message} — already set in ${setIn}` };
  return {
    checkId: spec.checkId,
    applied: false,
    message: spec.noConfigMessage ?? 'No compatible config file found',
  };
}
