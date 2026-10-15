import { createHash } from 'node:crypto';
import { parse } from '@babel/parser';

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
 * Babel's parser recurses once per bracket level and overflows Node's stack
 * at around 250 levels — a kilobyte of `[[[…]]]` that runs fine made the
 * whole file unparseable, so every AST check saw nothing in it. When that
 * happens the over-nested lines are blanked (line numbers kept) and the rest
 * parsed; SKL-002/MCP-035 report the nesting itself (`overNestedLines`).
 */
export function parseLenient(code: string): JsAst | undefined {
  try {
    return babelParse(code);
  } catch (err) {
    if (!(err instanceof RangeError)) return undefined;
  }
  const blank = new Set(overNestedLines(code));
  if (blank.size === 0) return undefined;
  try {
    return babelParse(code.split('\n').map((line, i) => (blank.has(i + 1) ? '' : line)).join('\n'));
  } catch {
    return undefined;
  }
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
