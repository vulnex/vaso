import { join } from 'node:path';
import type { CheckResult } from '../core/types.js';
import type { MCPServerSource } from './types.js';

/** `// === <relative path> ===` — the header a multi-file source puts before each file. */
const FILE_MARKER = /^\/\/ === (.+) ===$/;

interface FileSpan {
  /** 1-based line of the marker in the joined text. */
  markerLine: number;
  file: string;
}

function fileSpans(source: MCPServerSource): FileSpan[] {
  if (!source.sourceCode) return [];
  const spans: FileSpan[] = [];
  const lines = source.sourceCode.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const m = FILE_MARKER.exec(lines[i]);
    if (!m) continue;
    const file = source.sourceRoot ? join(source.sourceRoot, m[1])
      : source.packageName ? `${source.packageName}/${m[1]}` : m[1];
    spans.push({ markerLine: i + 1, file });
  }
  return spans;
}

/**
 * A server's files are joined into one text for analysis, so checks report
 * lines of the joined text against the server's entry (or package name).
 * Map each such evidence item to the file it is in and its line there.
 */
export function mapSourceEvidence(results: CheckResult[], sources: MCPServerSource[]): void {
  const tables = new Map<string, FileSpan[]>();
  for (const source of sources) {
    const spans = fileSpans(source);
    if (spans.length === 0) continue;
    for (const key of [source.localPath, source.packageName, source.serverName]) {
      if (key && !tables.has(key)) tables.set(key, spans);
    }
  }
  if (tables.size === 0) return;
  for (const result of results) {
    for (const e of result.evidence ?? []) {
      const spans = e.file !== undefined && e.line !== undefined ? tables.get(e.file) : undefined;
      if (!spans) continue;
      const span = [...spans].reverse().find((s) => s.markerLine < e.line!);
      if (!span) continue;
      e.file = span.file;
      e.line = e.line! - span.markerLine;
    }
  }
}
