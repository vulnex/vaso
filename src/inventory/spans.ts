import type { FSProvider } from '../core/fs-provider.js';
import type { McpServerItem } from '../core/types.js';

/**
 * Lines (1-based, inclusive) each MCP server's entry spans in its config
 * file, for findings that quote a bare config line (IOC-001's URL, CFG-002's
 * key) without naming the server. Kept beside the items, not on them: the
 * inventory reports don't carry line numbers.
 */
const spans = new WeakMap<McpServerItem, readonly [number, number]>();

export function serverSpan(item: McpServerItem): readonly [number, number] | undefined {
  return spans.get(item);
}

const escapeRegex = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/** Line of each character offset, by binary search over line starts. */
function lineOf(starts: number[], offset: number): number {
  let lo = 0;
  let hi = starts.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (starts[mid] <= offset) lo = mid;
    else hi = mid - 1;
  }
  return lo + 1;
}

/** Where a key (or a `"name"` member's value) was met: how often, and its first occurrence. */
interface Hit {
  count: number;
  /** Offset of the key's opening quote. */
  at: number;
  /** Offset of the value after `:` (and whitespace). */
  value: number;
  /** Containers open at the key, innermost last (two kept: the object and its parent). */
  object?: number;
  parent?: number;
}

/**
 * One pass over a JSON text: every object key by its raw (still escaped)
 * spelling, every `"name": "<value>"` member by its raw value, and where each
 * container closes. Looking a server up is then a map hit, not a scan of the
 * whole file per server — a ~/.claude.json with thousands of projects made
 * the per-server regex scans quadratic.
 */
interface JsonIndex {
  keys: Map<string, Hit>;
  names: Map<string, Hit>;
  /** Opening offset of each `{`/`[` → offset of its closing bracket. */
  ends: Map<number, number>;
}

function indexJson(text: string): JsonIndex {
  const keys = new Map<string, Hit>();
  const names = new Map<string, Hit>();
  const ends = new Map<number, number>();
  const stack: number[] = [];
  const note = (map: Map<string, Hit>, raw: string, hit: Omit<Hit, 'count'>) => {
    const seen = map.get(raw);
    if (seen) seen.count++;
    else map.set(raw, { count: 1, ...hit });
  };
  /** End offset (the closing quote) of the string opening at `from`. */
  const stringEnd = (from: number): number => {
    for (let i = from + 1; i < text.length; i++) {
      if (text[i] === '\\') i++;
      else if (text[i] === '"') return i;
    }
    return text.length;
  };
  const skipSpace = (from: number): number => {
    let i = from;
    while (i < text.length && /\s/.test(text[i])) i++;
    return i;
  };
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === '"') {
      const end = stringEnd(i);
      const colon = skipSpace(end + 1);
      if (text[colon] === ':') {
        const raw = text.slice(i + 1, end);
        const value = skipSpace(colon + 1);
        note(keys, raw, { at: i, value });
        if (raw === 'name' && text[value] === '"') {
          const valueEnd = stringEnd(value);
          note(names, text.slice(value + 1, valueEnd), { at: i, value, object: stack[stack.length - 1], parent: stack[stack.length - 2] });
        }
      }
      i = end;
    } else if (c === '{' || c === '[') {
      stack.push(i);
    } else if (c === '}' || c === ']') {
      const open = stack.pop();
      if (open !== undefined) ends.set(open, i);
    }
  }
  return { keys, names, ends };
}

/** The raw spelling a name has between quotes in JSON text. */
const rawJson = (name: string) => JSON.stringify(name).slice(1, -1);

/** `"name": {…}` — the one occurrence, when the name is a key exactly once. */
function jsonSpan(index: JsonIndex, text: string, starts: number[], name: string): [number, number] | undefined {
  const hit = index.keys.get(rawJson(name));
  if (!hit || hit.count !== 1 || text[hit.value] !== '{') return undefined;
  const end = index.ends.get(hit.value);
  return end === undefined ? undefined : [lineOf(starts, hit.at), lineOf(starts, end)];
}

/**
 * An array entry `{ "name": "<name>", … }` (Abacus.AI `mcpServers[]`, Atomic
 * Agent `mcp.servers[]`) — the one object in an array naming it exactly once.
 */
function jsonArrayEntrySpan(index: JsonIndex, text: string, starts: number[], name: string): [number, number] | undefined {
  const hit = index.names.get(rawJson(name));
  if (!hit || hit.count !== 1) return undefined;
  const { object, parent } = hit;
  if (object === undefined || parent === undefined || text[object] !== '{' || text[parent] !== '[') return undefined;
  const end = index.ends.get(object);
  return end === undefined ? undefined : [lineOf(starts, object), lineOf(starts, end)];
}

/** `name:` as a mapping key (YAML): until the next line indented no deeper. */
function yamlSpan(lines: string[], name: string): [number, number] | undefined {
  const re = new RegExp(`^(\\s*)(?:"${escapeRegex(name)}"|'${escapeRegex(name)}'|${escapeRegex(name)}):\\s*(?:#.*)?$`);
  const hits = lines.map((l, i) => [i, re.exec(l)] as const).filter(([, m]) => m);
  if (hits.length !== 1) return undefined;
  const [start, m] = hits[0];
  const indent = m![1].length;
  let end = start;
  for (let i = start + 1; i < lines.length; i++) {
    if (lines[i].trim() === '' || lines[i].trimStart().startsWith('#')) continue;
    if (lines[i].length - lines[i].trimStart().length <= indent) break;
    end = i;
  }
  return [start + 1, end + 1];
}

/** `[mcp_servers.<name>]` (TOML): until the next table header that isn't one of its subtables. */
function tomlSpan(lines: string[], name: string): [number, number] | undefined {
  const key = `(?:${escapeRegex(name)}|"${escapeRegex(name)}")`;
  const re = new RegExp(`^\\s*\\[\\s*mcp_servers\\.${key}\\s*\\]`);
  const start = lines.findIndex(l => re.test(l));
  if (start === -1) return undefined;
  const sub = new RegExp(`^\\s*\\[\\s*mcp_servers\\.${key}\\.`);
  let end = start;
  for (let i = start + 1; i < lines.length; i++) {
    if (/^\s*\[/.test(lines[i]) && !sub.test(lines[i])) break;
    if (lines[i].trim() !== '') end = i;
  }
  return [start + 1, end + 1];
}

/**
 * Record the line span of each server in its config file. A name that isn't
 * found exactly once (minified files, the same name in two scopes) gets no
 * span — no bare-line finding is linked to it.
 */
export async function recordServerSpans(items: McpServerItem[], fs: FSProvider): Promise<void> {
  const byFile = new Map<string, McpServerItem[]>();
  for (const item of items) {
    const list = byFile.get(item.configFile);
    if (list) list.push(item);
    else byFile.set(item.configFile, [item]);
  }
  for (const [file, list] of byFile) {
    let text: string;
    try {
      text = await fs.readFile(file);
    } catch {
      continue;
    }
    const lines = text.split('\n');
    const starts: number[] = [0];
    for (let i = 0; i < text.length; i++) if (text[i] === '\n') starts.push(i + 1);
    const kind = /\.toml$/i.test(file) ? 'toml' : /\.ya?ml$/i.test(file) ? 'yaml' : 'json';
    const index = kind === 'json' ? indexJson(text) : undefined;
    for (const item of list) {
      const span = kind === 'toml' ? tomlSpan(lines, item.name)
        : kind === 'yaml' ? yamlSpan(lines, item.name)
          : jsonSpan(index!, text, starts, item.name) ?? jsonArrayEntrySpan(index!, text, starts, item.name);
      if (span) spans.set(item, span);
    }
  }
}
