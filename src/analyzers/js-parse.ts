import { createHash } from 'node:crypto';
import { parse } from '@babel/parser';
import { VISITOR_KEYS } from '@babel/types';

export type JsAst = ReturnType<typeof parse>;

/**
 * Several MCP checks walk the same server source as an AST (MCP-005 taint,
 * MCP-034 string literals); resolved npm bundles run to megabytes, so parse
 * each distinct source once. A handful of ASTs at most — they are large.
 */
const MAX_CACHED_ASTS = 4;
const cache = new Map<string, JsAst | null>();

/** Parse JavaScript/TypeScript leniently; undefined when it isn't parseable. */
export function parseJs(code: string): JsAst | undefined {
  const key = createHash('sha1').update(code).digest('base64');
  if (cache.has(key)) {
    const hit = cache.get(key)!;
    // Refresh recency.
    cache.delete(key);
    cache.set(key, hit);
    return hit ?? undefined;
  }
  const ast = parseLenient(code) ?? null;
  if (cache.size >= MAX_CACHED_ASTS) cache.delete(cache.keys().next().value!);
  cache.set(key, ast);
  return ast ?? undefined;
}

function babelParse(code: string): JsAst {
  // With errorRecovery Babel builds an error object for every recoverable
  // syntax error, and capturing each one's stack dominated the parse of
  // garbage input (a 2 MB file of them: seconds). The errors' stacks are
  // never used.
  const limit = Error.stackTraceLimit;
  Error.stackTraceLimit = 0;
  try {
    return parse(code, {
      sourceType: 'unambiguous',
      plugins: ['typescript', 'jsx', 'decorators'],
      errorRecovery: true,
    });
  } finally {
    Error.stackTraceLimit = limit;
  }
}

/**
 * Files that are certainly not JavaScript/TypeScript. Skill trees hold shell
 * scripts, data and docs next to code; parsing them as JavaScript finds
 * nothing real and, with error recovery, can take seconds per file. A name
 * without a known extension (an MCP server name, an extensionless bin) is
 * still parsed.
 */
const NOT_JS_EXTENSIONS = new Set([
  '.sh', '.bash', '.zsh', '.fish', '.ps1', '.psm1', '.bat', '.cmd',
  '.json', '.jsonc', '.json5', '.yaml', '.yml', '.toml', '.ini', '.cfg', '.conf', '.env',
  '.txt', '.csv', '.tsv', '.log', '.xml', '.html', '.htm', '.css', '.scss', '.svg', '.md', '.mdx', '.rst',
  '.py', '.rb', '.go', '.rs', '.java', '.kt', '.swift', '.c', '.h', '.cc', '.cpp', '.hpp', '.cs', '.php', '.pl', '.lua', '.r', '.sql',
]);

/** Whether `filename` could hold JavaScript/TypeScript (see NOT_JS_EXTENSIONS). */
export function mayBeJavaScript(filename: string): boolean {
  const dot = filename.lastIndexOf('.');
  const slash = Math.max(filename.lastIndexOf('/'), filename.lastIndexOf('\\'));
  if (dot <= slash + 1) return true;
  return !NOT_JS_EXTENSIONS.has(filename.slice(dot).toLowerCase());
}

/**
 * Babel's parser recurses once per nesting level and overflows Node's stack
 * at around 250 — a kilobyte of `[[[…]]]`, a `1?1?…:1` chain, `!!!…1` or
 * nested templates, all of which run fine, made the whole file unparseable,
 * so every AST check saw nothing in it. When that happens the file is split
 * into top-level statements; each one Babel can't parse on its own is
 * blanked (newlines kept, so line numbers hold) and the rest parsed again.
 * The blanked lines are recorded (`evadedLines`) for SKL-002/MCP-035.
 */
export function parseLenient(code: string): JsAst | undefined {
  return parseLenientReport(code).ast;
}

const MAX_EVASION_RECORDS = 4096;
/** content hash → first lines of statements blanked to parse it ([] = parsed whole) */
const evasionRecords = new Map<string, number[]>();

function contentKey(code: string): string {
  return createHash('sha1').update(code).digest('base64');
}

function record(code: string, lines: number[]): void {
  if (evasionRecords.size >= MAX_EVASION_RECORDS) evasionRecords.delete(evasionRecords.keys().next().value!);
  evasionRecords.set(contentKey(code), lines);
}

export function parseLenientReport(code: string): { ast?: JsAst; evaded: number[] } {
  let text = code;
  let evaded: number[] = [];
  let ast: JsAst | undefined;
  try {
    ast = babelParse(code);
  } catch (err) {
    if (!(err instanceof RangeError)) {
      record(code, []);
      return { evaded: [] };
    }
    const bombs = topLevelSegments(code).filter(seg => {
      const segText = code.slice(seg.start, seg.end);
      if (!/\S/.test(segText)) return false;
      try {
        babelParse(segText);
        return false;
      } catch (e) {
        return e instanceof RangeError;
      }
    });
    evaded = bombs.map(b => b.line);
    text = blankRanges(code, bombs);
    try {
      ast = bombs.length > 0 ? babelParse(text) : undefined;
    } catch {
      ast = undefined;
    }
  }
  // Parsed, but nested deeper than the (recursive) traversal survives —
  // `!!!…1` or `a+b+…` thousands deep parse iteratively and then overflow
  // every AST check's walk
  const deep = ast ? ast.program.body.filter(stmt => astDeeperThan(stmt, AST_DEPTH_LIMIT)) : [];
  if (deep.length > 0) {
    evaded = [...evaded, ...deep.map(stmt => stmt.loc?.start.line ?? 1)].sort((a, b) => a - b);
    text = blankRanges(text, deep.map(stmt => ({ start: stmt.start ?? 0, end: stmt.end ?? 0 })));
    try {
      ast = babelParse(text);
    } catch {
      ast = undefined;
    }
  }
  record(code, evaded);
  return { ast, evaded };
}

/** AST depth past which a recursive walk risks overflowing the stack. */
const AST_DEPTH_LIMIT = 500;

/** Whether `node`'s subtree is deeper than `limit` — measured without recursion. */
function astDeeperThan(node: object, limit: number): boolean {
  const stack: Array<[Record<string, unknown>, number]> = [[node as Record<string, unknown>, 1]];
  while (stack.length > 0) {
    const [n, d] = stack.pop()!;
    if (d > limit) return true;
    for (const key of VISITOR_KEYS[n.type as string] ?? []) {
      const child = n[key];
      if (Array.isArray(child)) {
        for (const c of child) if (c && typeof c === 'object') stack.push([c as Record<string, unknown>, d + 1]);
      } else if (child && typeof child === 'object') {
        stack.push([child as Record<string, unknown>, d + 1]);
      }
    }
  }
  return false;
}

/** `code` with the given ranges replaced by spaces (newlines kept). */
function blankRanges(code: string, ranges: Array<{ start: number; end: number }>): string {
  let out = '';
  let at = 0;
  for (const r of [...ranges].sort((a, b) => a.start - b.start)) {
    if (r.start < at) continue;
    out += code.slice(at, r.start) + code.slice(r.start, r.end).replace(/[^\n]/g, ' ');
    at = r.end;
  }
  return out + code.slice(at);
}

/**
 * Lines (1-based) of the statements that had to be blanked for `code` to
 * parse, when it has been parsed (by `parseLenient`); undefined when it
 * hasn't been seen.
 */
export function recordedEvasion(code: string): number[] | undefined {
  return evasionRecords.get(contentKey(code));
}

interface Segment { start: number; end: number; line: number }

/**
 * Top-level statements of `code`, split at `;` or a newline outside any
 * bracket, string, template or comment. A single non-recursive pass — it
 * must work on exactly the input that overflows a recursive parser. Regex
 * literals aren't recognized (a quote or bracket inside one can merge or
 * split statements, which only makes the blanked region coarser).
 */
export function topLevelSegments(code: string): Segment[] {
  const out: Segment[] = [];
  let depth = 0;
  // Template nesting: each frame is a template literal (`tpl`) or a `${…}`
  // inside one, with the bracket depth it opened at
  const frames: Array<{ kind: 'tpl' | 'expr'; depth: number }> = [];
  let quote = '';
  let comment: '' | 'line' | 'block' = '';
  let start = 0;
  let startLine = 1;
  let line = 1;
  const cut = (end: number): void => {
    out.push({ start, end, line: startLine });
    start = end;
    startLine = line;
  };
  for (let i = 0; i < code.length; i++) {
    const c = code[i];
    const top = frames[frames.length - 1];
    if (c === '\n') {
      line++;
      if (comment === 'line') comment = '';
      if (quote) quote = ''; // an unterminated '…' or "…" ends at the line
      if (!comment && depth === 0 && frames.length === 0) cut(i + 1);
      continue;
    }
    if (comment === 'line') continue;
    if (comment === 'block') {
      if (c === '*' && code[i + 1] === '/') { comment = ''; i++; }
      continue;
    }
    if (quote) {
      if (c === '\\') i++;
      else if (c === quote) quote = '';
      continue;
    }
    if (top?.kind === 'tpl') {
      if (c === '\\') i++;
      else if (c === '`') frames.pop();
      else if (c === '$' && code[i + 1] === '{') { frames.push({ kind: 'expr', depth }); depth++; i++; }
      continue;
    }
    if (c === '/' && code[i + 1] === '/') { comment = 'line'; i++; continue; }
    if (c === '/' && code[i + 1] === '*') { comment = 'block'; i++; continue; }
    if (c === "'" || c === '"') { quote = c; continue; }
    if (c === '`') { frames.push({ kind: 'tpl', depth }); continue; }
    if (c === '(' || c === '[' || c === '{') depth++;
    else if (c === ')' || c === ']' || c === '}') {
      if (depth > 0) depth--;
      if (c === '}' && top?.kind === 'expr' && depth === top.depth) frames.pop();
    } else if (c === ';' && depth === 0 && frames.length === 0) {
      cut(i + 1);
    }
  }
  if (start < code.length) cut(code.length);
  return out;
}

/** Bracket depth past which code is treated as built to defeat analysis (Babel overflows near 250). */
export const ANALYSIS_NESTING_LIMIT = 200;

/**
 * 1-based lines where `(`/`[`/`{` nesting exceeds `limit`. A single pass that
 * skips string, template and comment contents; regex literals aren't
 * recognized, which only matters for brackets inside them.
 */
export function overNestedLines(code: string, limit = ANALYSIS_NESTING_LIMIT): number[] {
  const out: number[] = [];
  let depth = 0;
  let line = 1;
  let flagged = false;
  let quote = '';
  let comment: '' | 'line' | 'block' = '';
  for (let i = 0; i < code.length; i++) {
    const c = code[i];
    if (c === '\n') {
      line++;
      flagged = false;
      if (comment === 'line') comment = '';
      if (quote === "'" || quote === '"') quote = '';
      continue;
    }
    if (comment === 'line') continue;
    if (comment === 'block') {
      if (c === '*' && code[i + 1] === '/') { comment = ''; i++; }
      continue;
    }
    if (quote) {
      if (c === '\\') i++;
      else if (c === quote) quote = '';
      continue;
    }
    if (c === '/' && code[i + 1] === '/') { comment = 'line'; i++; continue; }
    if (c === '/' && code[i + 1] === '*') { comment = 'block'; i++; continue; }
    if (c === "'" || c === '"' || c === '`') { quote = c; continue; }
    if (c === '(' || c === '[' || c === '{') {
      if (++depth > limit && !flagged) { out.push(line); flagged = true; }
    } else if ((c === ')' || c === ']' || c === '}') && depth > 0) {
      depth--;
    }
  }
  return out;
}

export interface SourceChunk {
  /** 1-based line of the chunk's first line in the full source. */
  startLine: number;
  code: string;
}

/** `// === dist/tools.js ===` — the per-file header `--resolve-packages` writes. */
const FILE_MARKER = /^\/\/ === .+ ===$/;

/**
 * Source split back into the files it was concatenated from (npm packages
 * resolved with `--resolve-packages` are several modules joined with
 * `// === path ===` headers). Joined ES modules don't parse as one program —
 * duplicate top-level names, mixed module types — so each file is parsed on
 * its own. Single-file source is one chunk.
 *
 * A bin file's `#!/usr/bin/env node` lands on the line after its header, where
 * it is a syntax error (a hashbang is only legal on line 1) and the whole file
 * fails to parse; it is turned into a comment of the same length.
 */
export function sourceChunks(code: string): SourceChunk[] {
  const lines = code.split('\n');
  const chunks: SourceChunk[] = [];
  const chunk = (from: number, to: number): SourceChunk => {
    const part = lines.slice(from, to);
    if (FILE_MARKER.test(part[0] ?? '') && part[1]?.startsWith('#!')) part[1] = `//${part[1].slice(2)}`;
    return { startLine: from + 1, code: part.join('\n') };
  };
  let start = 0;
  for (let i = 0; i < lines.length; i++) {
    if (i > start && FILE_MARKER.test(lines[i])) {
      chunks.push(chunk(start, i));
      start = i;
    }
  }
  chunks.push(chunk(start, lines.length));
  return chunks;
}
