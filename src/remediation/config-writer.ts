import { readRegularFile, writeRegularFile, chmodNoFollow, regularMode, UnsafeTargetError } from './safe-file.js';
import YAML from 'yaml';
import { parse as parseTOML, stringify as stringifyTOML } from 'smol-toml';
import type { FixResult, ParsedConfig } from '../core/types.js';
import { getNestedValue, setNestedValue } from '../core/utils.js';
import { loadConfig } from '../core/config-loader.js';
import { parseJsonLenient } from '../core/jsonc.js';

/**
 * Update or insert a key=value pair in a .env file.
 * Preserves comments and line ordering. The line rewritten is the one the
 * loader reads (parseEnv in config-loader, like dotenv): the last assignment
 * of the key, `export KEY=…` included (the `export` is kept).
 */
export async function updateEnvFile(filePath: string, key: string, value: string): Promise<void> {
  const content = (await readRegularFile(filePath)).toString('utf-8');
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
      lines[i] = `${exported ? 'export ' : ''}${key}=${value}`;
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
    lines.splice(insertIndex, 0, `${key}=${value}`);
  }

  await writeRegularFile(filePath, lines.join('\n'));
}

/**
 * Update a nested value in a JSON file, detecting and preserving indentation.
 */
export async function updateJsonFile(filePath: string, keyPath: string, value: unknown): Promise<void> {
  const content = (await readRegularFile(filePath)).toString('utf-8');
  // JSONC/JSON5 configs load (see config-loader) — the fix must read them too.
  // They are written back as plain JSON, which both formats accept.
  const obj = parseJsonLenient(content.replace(/^\uFEFF/, '')) as Record<string, unknown>;

  // Detect indentation from the file
  const indentMatch = content.match(/^(\s+)/m);
  const indent = indentMatch ? indentMatch[1].length : 2;

  setNestedValue(obj, keyPath, value);
  await writeRegularFile(filePath, JSON.stringify(obj, null, indent) + '\n');
}

/**
 * Update a nested value in a YAML file using Document API to preserve comments and structure.
 */
export async function updateYamlFile(filePath: string, keyPath: string, value: unknown): Promise<void> {
  const content = (await readRegularFile(filePath)).toString('utf-8');
  const doc = YAML.parseDocument(content);
  const keys = keyPath.split('.');
  doc.setIn(keys, value);
  await writeRegularFile(filePath, doc.toString());
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
 * Edit one key in TOML text in place: replace the value of an existing
 * `key = …` line (keeping indentation and a trailing comment), else add the
 * key under the deepest `[table]` header on its path, else append a new
 * table. Returns undefined when the layout isn't one this can follow.
 */
function editTomlText(content: string, path: string[], value: unknown): string | undefined {
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
      const close = t.lastIndexOf(']');
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
      if ([...current, ...keySegs].join(SEP) === want) {
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
 * before it is written. Layouts the line editor can't follow (inline tables,
 * arrays of tables) fall back to a full smol-toml re-serialization.
 */
export async function updateTomlFile(filePath: string, keyPath: string, value: unknown): Promise<void> {
  const content = (await readRegularFile(filePath)).toString('utf-8');
  const obj = parseTOML(content) as Record<string, unknown>;
  setNestedValue(obj, keyPath, value);

  const edited = editTomlText(content, keyPath.split('.'), value);
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
      // otherwise the file doesn't exist
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
 * For json/yaml/toml files, keyPath is dot-separated (e.g., 'gateway.host').
 */
export async function updateConfigValue(config: ParsedConfig, keyPath: string, value: unknown): Promise<void> {
  switch (config.format) {
    case 'env':
      await updateEnvFile(config.filePath, keyPath, String(value));
      break;
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
  /** Dot-separated key path for json/yaml/toml configs. Omit → structured files are skipped. */
  path?: string;
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
