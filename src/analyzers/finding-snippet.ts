/**
 * The source line an analyzer finding quotes. Findings keep a short
 * `snippet` (the first 120 characters) and, when the line is longer, the
 * whole line in `sourceLine`, so a consumer that masks secrets can mask the
 * full line before it cuts — a cut never lands inside a value it has not
 * masked yet.
 */

export const FINDING_SNIPPET_MAX = 120;

export interface FindingSnippet {
  snippet: string;
  /** The whole line, when `snippet` is a cut of it. */
  sourceLine?: string;
}

export function cutLine(text: string): FindingSnippet {
  return text.length > FINDING_SNIPPET_MAX
    ? { snippet: text.slice(0, FINDING_SNIPPET_MAX), sourceLine: text }
    : { snippet: text };
}
