/**
 * Line-sized units of MCP server source for the regex-based checks.
 *
 * Published packages are mostly minified bundles where one physical line holds
 * kilobytes of unrelated statements, so a pattern like `token.*[?&].*=` or
 * `redirect.*params\.` matches across code that has nothing to do with itself.
 * Long lines are split at statement boundaries (`;`) — a pattern then has to
 * hold within one statement, as it would in formatted source. Each segment
 * keeps its physical line number for evidence.
 */

export interface SourceSegment {
  /** 1-based physical line the segment comes from. */
  line: number;
  text: string;
}

/** Lines longer than this are treated as minified and split. */
const MINIFIED_LINE = 400;

export function isCommentLine(text: string): boolean {
  const t = text.trimStart();
  return t.startsWith('//') || t.startsWith('*') || t.startsWith('/*') || t.startsWith('#');
}

/**
 * Source split into segments, comment lines dropped. Ordinary lines are one
 * segment each; minified lines become one segment per statement.
 */
export function sourceSegments(code: string): SourceSegment[] {
  const out: SourceSegment[] = [];
  const lines = code.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const text = lines[i];
    if (isCommentLine(text)) continue;
    if (text.length <= MINIFIED_LINE) {
      out.push({ line: i + 1, text });
      continue;
    }
    for (const statement of text.split(/(?<=;)/)) {
      if (statement.trim()) out.push({ line: i + 1, text: statement });
    }
  }
  return out;
}

/** Text of the segments within `radius` of index `i`, for "is X nearby" tests. */
export function nearbyText(segments: SourceSegment[], i: number, radius: number): string {
  return segments
    .slice(Math.max(0, i - radius), Math.min(segments.length, i + radius + 1))
    .map((s) => s.text)
    .join('\n');
}

/** Snippet for evidence: trimmed and capped. */
export function segmentSnippet(segment: SourceSegment, max = 120): string {
  return segment.text.trim().slice(0, max);
}

/**
 * The text with string-literal contents blanked (`"…"`, `'…'`, and the text
 * parts of template literals; `${…}` expressions are kept). Lets a check ask
 * whether *code* mentions a token rather than a log message saying "token".
 */
export function withoutStringText(text: string): string {
  let out = '';
  let quote: string | undefined; // current string delimiter
  const templateDepth: number[] = []; // brace depth at each open `${`
  let braces = 0;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (quote) {
      if (c === '\\') { i++; continue; }
      if (quote === '`' && c === '$' && text[i + 1] === '{') {
        out += '${';
        i++;
        templateDepth.push(braces);
        braces++;
        quote = undefined;
        continue;
      }
      if (c === quote) { out += c; quote = undefined; }
      continue;
    }
    if (c === '"' || c === "'" || c === '`') { out += c; quote = c; continue; }
    if (c === '{') braces++;
    if (c === '}') {
      braces--;
      if (templateDepth.length > 0 && braces === templateDepth[templateDepth.length - 1]) {
        templateDepth.pop();
        out += c;
        quote = '`'; // back inside the template text
        continue;
      }
    }
    out += c;
  }
  return out;
}
