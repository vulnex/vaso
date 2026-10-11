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
  let ast: JsAst | null;
  try {
    ast = parse(code, {
      sourceType: 'unambiguous',
      plugins: ['typescript', 'jsx', 'decorators'],
      errorRecovery: true,
    });
  } catch {
    ast = null;
  }
  if (cache.size >= MAX_CACHED_ASTS) cache.delete(cache.keys().next().value!);
  cache.set(key, ast);
  return ast ?? undefined;
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
 */
export function sourceChunks(code: string): SourceChunk[] {
  const lines = code.split('\n');
  const chunks: SourceChunk[] = [];
  let start = 0;
  for (let i = 0; i < lines.length; i++) {
    if (i > start && FILE_MARKER.test(lines[i])) {
      chunks.push({ startLine: start + 1, code: lines.slice(start, i).join('\n') });
      start = i;
    }
  }
  chunks.push({ startLine: start + 1, code: lines.slice(start).join('\n') });
  return chunks;
}
