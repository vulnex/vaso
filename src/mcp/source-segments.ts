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

import { pythonStringLines } from '../analyzers/python-sinks.js';

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
 * segment each; minified lines become one segment per statement. For Python
 * (`{ python: true }`) docstring bodies are dropped too: a docstring that
 * says the host "probes ``/authorize``" documents the code, it is not code.
 */
export function sourceSegments(code: string, opts: { python?: boolean } = {}): SourceSegment[] {
  const out: SourceSegment[] = [];
  const lines = code.split('\n');
  // an assigned `x = """…` string is data and kept
  const strings = opts.python ? pythonStringLines(lines) : [];
  for (let i = 0; i < lines.length; i++) {
    const text = lines[i];
    if (strings[i] === 'doc') continue;
    if (isCommentLine(text)) continue;
    if (text.length <= MINIFIED_LINE) {
      out.push({ line: i + 1, text });
      continue;
    }
    for (const statement of text.split(/(?<=;)/)) {
      if (!statement.trim()) continue;
      for (const piece of boundedPieces(statement)) out.push({ line: i + 1, text: piece });
    }
  }
  return out;
}

/**
 * Segments are at most this long. A statement without `;` (a megabyte data
 * URI, an object literal, a line built to stall a check) otherwise reaches
 * every line regex whole, and one with a quadratic worst case runs for
 * minutes.
 */
export const MAX_SEGMENT = 2000;

/**
 * A long statement in pieces of at most MAX_SEGMENT, cut after the last `,`,
 * `{`, `}` or space outside a string when there is one in the second half of
 * the window. A string longer than that is cut inside, closed with its quote
 * and reopened in the next piece, so each piece still blanks it as a string
 * (`withoutStringText`).
 */
function boundedPieces(statement: string): string[] {
  if (statement.length <= MAX_SEGMENT) return [statement];
  const out: string[] = [];
  let start = 0;
  let reopen = ''; // quote the current piece starts inside
  while (statement.length - start > MAX_SEGMENT - reopen.length) {
    const limit = start + MAX_SEGMENT - reopen.length - 1;
    let quote = reopen;
    let lastCut = -1;
    let i = start;
    for (; i < limit; i++) {
      const c = statement[i];
      if (quote) {
        if (c === '\\') {
          if (i + 1 >= limit) break; // keep an escape with what it escapes
          i++;
        } else if (c === quote) {
          quote = '';
        }
        continue;
      }
      if (c === '"' || c === "'" || c === '`') quote = c;
      else if (c === ',' || c === '{' || c === '}' || c === ' ') lastCut = i + 1;
    }
    if (lastCut > start + (limit - start) / 2) {
      out.push(reopen + statement.slice(start, lastCut));
      reopen = '';
      start = lastCut;
    } else {
      out.push(reopen + statement.slice(start, i) + quote);
      reopen = quote;
      start = i;
    }
  }
  out.push(reopen + statement.slice(start));
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
  return splitStrings(text).code;
}

/**
 * `withoutStringText`, plus the string contents it blanked: one entry per
 * literal, and per text part of a template literal (escapes kept as written).
 */
export function splitStrings(text: string): { code: string; strings: string[] } {
  let out = '';
  const strings: string[] = [];
  let current = '';
  let quote: string | undefined; // current string delimiter
  const templateDepth: number[] = []; // brace depth at each open `${`
  let braces = 0;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (quote) {
      if (c === '\\') { current += text.slice(i, i + 2); i++; continue; }
      if (quote === '`' && c === '$' && text[i + 1] === '{') {
        out += '${';
        i++;
        templateDepth.push(braces);
        braces++;
        quote = undefined;
        strings.push(current);
        continue;
      }
      if (c === quote) { out += c; quote = undefined; strings.push(current); continue; }
      current += c;
      continue;
    }
    if (c === '"' || c === "'" || c === '`') { out += c; quote = c; current = ''; continue; }
    if (c === '{') braces++;
    if (c === '}') {
      braces--;
      if (templateDepth.length > 0 && braces === templateDepth[templateDepth.length - 1]) {
        templateDepth.pop();
        out += c;
        quote = '`'; // back inside the template text
        current = '';
        continue;
      }
    }
    out += c;
  }
  if (quote) strings.push(current);
  return { code: out, strings };
}

/**
 * A string constant declared, not a request made: `const AUTHORIZE_PATH =
 * "/oauth/authorize";`, or a string-to-string map entry (`"/authorize":
 * "/oauth/authorize",` in a route table).
 */
const STRING_CONSTANT = /^\s*(?:export\s+)?(?:const|let|var)?\s*[\w$.]+\s*[:=]\s*(['"`])[^'"`$]*\1\s*[;,]?\s*$/;
const STRING_MAP_ENTRY = /^\s*(['"])[^'"]*\1\s*:\s*(['"`])[^'"`$?]*\2\s*,?\s*$/;
export function isStringConstant(text: string): boolean {
  return STRING_CONSTANT.test(text) || STRING_MAP_ENTRY.test(text);
}

/**
 * Text from segment `i` to the end of the block it sits in: braces for
 * JS/TS (until the enclosing `}`), indentation for Python (until a line
 * indented less than this one). A flow's parameters (PKCE, state) are often
 * set further down the same function than a fixed window reaches. Capped.
 */
export function blockText(segments: SourceSegment[], i: number, python = false, cap = 400): string {
  const out: string[] = [];
  const indentOf = (t: string) => t.length - t.trimStart().length;
  const base = indentOf(segments[i]?.text ?? '');
  let depth = 0;
  let opened = false; // the start line opens its own block (a function header)
  for (let k = i; k < segments.length && k < i + cap; k++) {
    const text = segments[k].text;
    if (python) {
      // a `def …:` header's body is indented deeper: stop at the next line
      // back at (or left of) its own indentation
      if (k > i && text.trim() !== '' && (indentOf(text) < base || (opened && indentOf(text) === base))) break;
      if (k === i && /:\s*$/.test(text)) opened = true;
    } else {
      for (const c of withoutStringText(text)) {
        if (c === '{') depth++;
        else if (c === '}') depth--;
      }
      if (k === i && depth > 0) opened = true;
    }
    out.push(text);
    if (!python && (depth < 0 || (opened && depth === 0))) break;
  }
  return out.join('\n');
}
