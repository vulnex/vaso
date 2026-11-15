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

/** End offset of the JSON value starting at `from` (an object or array), or undefined. */
function jsonValueEnd(text: string, from: number): number | undefined {
  let depth = 0;
  let inString = false;
  for (let i = from; i < text.length; i++) {
    const c = text[i];
    if (inString) {
      if (c === '\\') i++;
      else if (c === '"') inString = false;
      continue;
    }
    if (c === '"') inString = true;
    else if (c === '{' || c === '[') depth++;
    else if (c === '}' || c === ']') {
      depth--;
      if (depth === 0) return i;
    } else if (depth === 0 && !/\s/.test(c)) return undefined;
  }
  return undefined;
}

/** `"name": {…}` — the one occurrence, when the name is a key exactly once. */
function jsonSpan(text: string, starts: number[], name: string): [number, number] | undefined {
  const re = new RegExp(`"${escapeRegex(JSON.stringify(name).slice(1, -1))}"\\s*:\\s*`, 'g');
  const hits = [...text.matchAll(re)];
  if (hits.length !== 1) return undefined;
  const valueStart = hits[0].index! + hits[0][0].length;
  if (text[valueStart] !== '{') return undefined;
  const end = jsonValueEnd(text, valueStart);
  return end === undefined ? undefined : [lineOf(starts, hits[0].index!), lineOf(starts, end)];
}

/** Offsets of the containers (`{` / `[`) open at `offset`, outermost first. */
function openContainers(text: string, offset: number): number[] {
  const stack: number[] = [];
  let inString = false;
  for (let i = 0; i < offset; i++) {
    const c = text[i];
    if (inString) {
      if (c === '\\') i++;
      else if (c === '"') inString = false;
      continue;
    }
    if (c === '"') inString = true;
    else if (c === '{' || c === '[') stack.push(i);
    else if (c === '}' || c === ']') stack.pop();
  }
  return stack;
}

/**
 * An array entry `{ "name": "<name>", … }` (Abacus.AI `mcpServers[]`, Atomic
 * Agent `mcp.servers[]`) — the one object in an array naming it exactly once.
 */
function jsonArrayEntrySpan(text: string, starts: number[], name: string): [number, number] | undefined {
  const re = new RegExp(`"name"\\s*:\\s*"${escapeRegex(JSON.stringify(name).slice(1, -1))}"`, 'g');
  const hits = [...text.matchAll(re)];
  if (hits.length !== 1) return undefined;
  const open = openContainers(text, hits[0].index!);
  const objectStart = open[open.length - 1];
  const parent = open[open.length - 2];
  if (objectStart === undefined || parent === undefined || text[objectStart] !== '{' || text[parent] !== '[') return undefined;
  const end = jsonValueEnd(text, objectStart);
  return end === undefined ? undefined : [lineOf(starts, objectStart), lineOf(starts, end)];
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
  for (const item of items) byFile.set(item.configFile, [...(byFile.get(item.configFile) ?? []), item]);
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
    for (const item of list) {
      const span = kind === 'toml' ? tomlSpan(lines, item.name)
        : kind === 'yaml' ? yamlSpan(lines, item.name)
          : jsonSpan(text, starts, item.name) ?? jsonArrayEntrySpan(text, starts, item.name);
      if (span) spans.set(item, span);
    }
  }
}
