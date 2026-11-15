/**
 * Source text quoted in an MCP finding. A credential MCP-003 flags in a
 * server's source is masked wherever another check quotes that source —
 * prose (`"use password <pw>"`), an argument, a URL — not just where a
 * `key: value` shape lets the report masker see it. Masking happens on the
 * whole line, before the cut: analyzer findings carry the full line
 * (`sourceLine`) whenever their short `snippet` is a cut of it.
 */

import { findSourceSecretValues } from '../analyzers/source-secrets.js';
import type { FindingSnippet } from '../analyzers/finding-snippet.js';
import { isPlaceholderSecret, isSecretReference, truncateSnippet } from '../core/patterns.js';
import { isKnownSecretValue, looksRandom } from '../analyzers/secret-values.js';
import type { MCPServerSource } from './types.js';

const valuesBySource = new WeakMap<object, string[]>();
const valuesByCode = new Map<string, string[]>();
/** Characters of a value the mask shape itself shows. */
const MASK_SHOWN = 4;
/** Masking a long line looks at this much of it first. */
const MASK_WINDOW = 4096;

function secretValues(source: Pick<MCPServerSource, 'sourceCode'>): string[] {
  const cached = valuesBySource.get(source);
  if (cached) return cached;
  const code = source.sourceCode ?? '';
  let values = valuesByCode.get(code);
  if (!values) {
    values = findSourceSecretValues(code).sort((a, b) => b.length - a.length);
    valuesByCode.clear();
    valuesByCode.set(code, values);
  }
  valuesBySource.set(source, values);
  return values;
}

function maskValue(value: string): string {
  return `${value.slice(0, MASK_SHOWN)}… (${value.length} chars)`;
}

function maskAll(text: string, values: string[]): string {
  let out = text;
  for (const value of values) {
    if (out.includes(value)) out = out.split(value).join(maskValue(value));
  }
  return out;
}

/**
 * The longest start of a value (more than the mask shows) that `text` ends
 * with, ignoring a trailing cut marker — what is left of a value a cut
 * went through.
 */
function cutValueAtEnd(text: string, values: string[]): { at: number; value: string } | undefined {
  const marker = /(?: ?\.\.\.|…)?\s*$/.exec(text);
  const end = marker ? marker.index : text.length;
  let best: { at: number; value: string } | undefined;
  for (const value of values) {
    for (let k = Math.min(value.length - 1, end); k > MASK_SHOWN; k--) {
      if (best && k <= end - best.at) break;
      if (text.startsWith(value.slice(0, k), end - k)) {
        best = { at: end - k, value };
        break;
      }
    }
  }
  return best;
}

/** `text` with every secret value flagged in `source` masked. */
export function maskSourceSecrets(source: Pick<MCPServerSource, 'sourceCode'>, text: string): string {
  const values = secretValues(source);
  if (values.length === 0) return text;
  const out = maskAll(text, values);
  // A value an earlier cut left at the end of the text
  const cut = cutValueAtEnd(out, values);
  if (!cut) return out;
  const marker = /(?: ?\.\.\.|…)?\s*$/.exec(out);
  return `${out.slice(0, cut.at)}${maskValue(cut.value)}${marker ? out.slice(marker.index) : ''}`;
}

/**
 * A source line or statement quoted in a finding: secrets masked, then cut
 * to `max`. `prose` also masks credentials written out in prose (text that
 * MCP-034 quotes as a directive).
 */
export function sourceSnippet(source: Pick<MCPServerSource, 'sourceCode'>, text: string, max = 120, prose = false): string {
  const line = text.trim();
  const values = secretValues(source);
  let masked = line;
  if (values.length > 0) {
    // Mask a window of a long line; when masking shrank it so far that the
    // cut could reach the window's end, mask the whole line instead
    const longest = values[0].length;
    if (line.length > MASK_WINDOW + longest) {
      masked = maskAll(line.slice(0, MASK_WINDOW + longest), values);
      if (masked.length < max + 2 * longest + 8) masked = maskAll(line, values);
    } else {
      masked = maskAll(line, values);
    }
  }
  return truncateSnippet(prose ? maskProseSecrets(masked) : masked, max);
}

/** The snippet of an analyzer finding: the full line masked then cut, when the finding carries it. */
export function findingSnippet(source: Pick<MCPServerSource, 'sourceCode'>, finding: FindingSnippet): string {
  return finding.sourceLine !== undefined
    ? sourceSnippet(source, finding.sourceLine)
    : maskSourceSecrets(source, finding.snippet);
}

/**
 * A credential named in prose: `The admin password is Hunter7-…`,
 * `token: …`, `use passphrase "…"`. The value is one unbroken run after the
 * credential word (and an optional `is` / `was` / `:` / `=`).
 */
const PROSE_SECRET = /(?<![A-Za-z0-9_])(?:password|passwd|passphrase|pwd|pin|secret|token|api[ _-]?key|access[ _-]?key|private[ _-]?key|credentials?)(?![A-Za-z0-9_])(?:\s*(?:[:=]|\bis\b|\bwas\b|\bset to\b|\bequals\b))?\s*["'`]?([^\s"'`,;()[\]{}<>]{8,})/gi;

function proseSecretValue(run: string): string | undefined {
  const value = run.replace(/[.!?:]+$/, '');
  if (value.length < 8 || isPlaceholderSecret(value) || isSecretReference(value) || /^[a-z][a-z0-9+.-]*:\/\//i.test(value)) return undefined;
  // a word or a phrase (`required`, `pass-through`) is not a credential
  if (!/[A-Za-z]/.test(value)) return undefined;
  if (/\d/.test(value) || looksRandom(value, 8) || isKnownSecretValue(value)) return value;
  return undefined;
}

/** `text` with credentials written out in prose masked (MCP-034 quotes prose). */
export function maskProseSecrets(text: string): string {
  return text.replace(PROSE_SECRET, (match: string, run: string) => {
    const value = proseSecretValue(run);
    if (!value) return match;
    const at = match.lastIndexOf(run);
    return `${match.slice(0, at)}${maskValue(value)}${run.slice(value.length)}`;
  });
}
