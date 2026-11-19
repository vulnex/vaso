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
  // a short value (a PIN, a 7-character password) shows less of itself, or nothing
  const shown = value.length >= 12 ? MASK_SHOWN : value.length >= 8 ? 2 : 0;
  return `${value.slice(0, shown)}… (${value.length} chars)`;
}

/**
 * Values by a hash of their first `width` characters, to find the few a text
 * can hold: a rolling hash reads each position of the text once.
 */
interface ValueIndex {
  width: number;
  /** BASE ** (width - 1), to drop the character leaving the window. */
  lead: number;
  byStart: Map<number, string[]>;
  /** Each value's place in the values' order (longest first). */
  rank: Map<string, number>;
}
const valueIndexes = new WeakMap<string[], ValueIndex | null>();
/** Below this many values a plain scan is as fast as the index. */
const INDEX_MIN_VALUES = 32;
const BASE = 31;

function startHash(text: string, from: number, width: number): number {
  let h = 0;
  for (let i = 0; i < width; i++) h = (Math.imul(h, BASE) + text.charCodeAt(from + i)) | 0;
  return h;
}

function valueIndex(values: string[]): ValueIndex | undefined {
  let index = valueIndexes.get(values);
  if (index === undefined) {
    const width = Math.min(8, ...values.map((v) => v.length));
    index = null;
    if (values.length >= INDEX_MIN_VALUES && width >= 4) {
      const byStart = new Map<number, string[]>();
      for (const v of values) {
        const key = startHash(v, 0, width);
        const list = byStart.get(key);
        if (list) list.push(v);
        else byStart.set(key, [v]);
      }
      let lead = 1;
      for (let i = 1; i < width; i++) lead = Math.imul(lead, BASE);
      index = { width, lead, byStart, rank: new Map(values.map((v, i) => [v, i])) };
    }
    valueIndexes.set(values, index);
  }
  return index ?? undefined;
}

function maskAll(text: string, values: string[]): string {
  // Many values: only those whose start occurs in the text can be in it
  // (each line was scanned for every value — 10k values × 10k lines)
  let candidates = values;
  const index = valueIndex(values);
  if (index) {
    const { width, lead, byStart } = index;
    const present = new Set<string>();
    if (text.length >= width) {
      let h = startHash(text, 0, width);
      for (let i = 0; ; i++) {
        const list = byStart.get(h);
        if (list) for (const v of list) if (text.startsWith(v, i)) present.add(v);
        if (i + width >= text.length) break;
        h = (Math.imul(h - Math.imul(text.charCodeAt(i), lead), BASE) + text.charCodeAt(i + width)) | 0;
      }
    }
    if (present.size === 0) return text;
    // in the values' own order (longest first), as the plain scan masks them
    candidates = [...present].sort((a, b) => index.rank.get(a)! - index.rank.get(b)!);
  }
  let out = text;
  for (const value of candidates) {
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
 * `token: …`, `use passphrase "…"`, `the password for the admin account is: …`,
 * `password -> …`, `Passphrase - …`, `The password, which is …`, `was set
 * to …`, `**Password:** …`, `<b>Password:</b> …`, `Use the password (…)`.
 * The value is one unbroken run after the credential word (and an optional
 * connector), or a quoted phrase (also in typographic quotes).
 * `pass` counts only with a connector (`the pass is …`): alone it is a verb.
 */
const PROSE_SECRET = /(?<![A-Za-z0-9_])(password|passwd|pass ?phrase|pass ?code|pwd|pin ?code|pin|secret|token|api[ _-]?key|access[ _-]?key|private[ _-]?key|credentials?|key|pat|pass(?=\s*(?:[:=：]|->|=>|\bis\b|\bwas\b)))(?![A-Za-z0-9_])(?:\s+number\b)?(?:\s+(?:for|of)\s+(?:(?:the|an?|your|our|this|that)\s+)?[\w.@-]{1,64}(?:\s+(?!(?:is|was|set|equals)\b)[\w.@-]{1,32}){0,5})?(?:\s*(->|=>|[:=：—–]|-(?=\s)|,\s*which\s+(?:is|was)\b|\b(?:is|was|has been)\s+(?:set|changed|reset)\s+to\b|\b(?:is|was)\b(?:\s*[:=：])?|\bset to\b|\bequals\b))?(?:\s*(?:\*{1,2}|_{1,2}|<\/?[A-Za-z]+>))*\s*(?:"([^"\n]{8,80})"|“([^”\n]{8,80})”|'([^'\n]{8,80})'|‘([^’\n]{8,80})’|["'`(]?([^\s"'`,;()[\]{}<>“”‘’]{4,}))/gi;

/** Credential words a person types: whatever is named as one after `is` / `:` is masked unless it is a plain word. */
const TYPED_SECRET = /^(?:password|passwd|pass ?phrase|pass ?code|pwd|pin ?code|pin|pass)$/i;
/** A user/password pair: `Credentials: admin / <pw>`, `Login with admin/<pw>`, `use admin/<pw> to log in`. */
const CREDENTIAL_PAIR = /(?<![A-Za-z0-9_])(?:credentials?\s*[:=：]?|log ?in\s+(?:with|as|using)\s*:?|use(?=\s+[\w.@+-]{1,64}\s*\/\s*[^\s"'`,;()<>/]{6,80}\s+to\s+(?:log ?in|sign ?in)))\s*[\w.@+-]{1,64}\s*\/\s*([^\s"'`,;()<>/]{6,80})/gi;
/** Words after a passphrase's first word (`The passphrase is correct horse battery staple`). */
const PHRASE_WORDS = /^(?:[ \t]+[A-Za-z0-9]+){1,7}/;
/** Words of ordinary prose: a quoted phrase holding one is a sentence, not a passphrase. */
const PROSE_WORDS = new Set([
  'the', 'a', 'an', 'you', 'your', 'yours', 'to', 'of', 'in', 'on', 'for', 'is', 'are', 'be', 'that', 'this', 'it', 'with', 'as',
  'at', 'by', 'from', 'or', 'and', 'not', 'no', 'must', 'should', 'will', 'can', 'may', 'here', 'there', 'enter', 'use', 'set',
  'same', 'least', 'most', 'than', 'chars', 'characters', 'long', 'required', 'when', 'if', 'we', 'our', 'my', 'me', 'please',
  'do', 'does', 'have', 'has', 'was', 'were', 'one', 'any', 'all', 'only', 'new', 'old', 'current',
]);

function proseSecretValue(run: string, keyword: string, connector: string | undefined, quoted: boolean): string | undefined {
  const value = quoted ? run : run.replace(/[.!?:]+$/, '');
  const typed = TYPED_SECRET.test(keyword);
  // a quoted phrase after `password is`: three or more words, none of them prose (`"moon lamp kettle 77"`)
  if (/\s/.test(value)) {
    const words = value.trim().split(/\s+/);
    // (`"my dog has fleas 42"`: a few prose words in a phrase; `"must be at least 12 chars"` is mostly prose)
    if (typed && (connector || quoted) && words.length >= 3 && words.every((w) => /^[A-Za-z0-9]+$/.test(w))
      && words.filter((w) => PROSE_WORDS.has(w.toLowerCase())).length * 2 < words.length) return value;
    // else its first word, as when unquoted: `"Hunter8Zebra Kettle"`
    return /^\s/.test(value) ? undefined : proseSecretValue(value.split(/\s/)[0], keyword, connector, false);
  }
  // a PIN or numeric passcode: `Your PIN is 48291173`, `Your PIN is 4829` (not a year: `The PIN is 2024`)
  if (/^\d+$/.test(value)) {
    const pin = /^pin/i.test(keyword) && value.length >= 4 && !/^(?:19|20)\d\d$/.test(value);
    return typed && connector && (value.length >= 6 || pin) ? value : undefined;
  }
  // a short typed password with letters and digits: `password is Lmp3Zb7`
  if (typed && connector && value.length >= 6 && value.length < 8 && /\d/.test(value) && /[A-Za-z]/.test(value)
    && !isPlaceholderSecret(value) && !isSecretReference(value)) return value;
  if (value.length < 8 || isPlaceholderSecret(value) || isSecretReference(value) || /^[a-z][a-z0-9+.-]*:\/\//i.test(value)) return undefined;
  // a word or a phrase (`required`, `pass-through`) is not a credential
  if (!/[A-Za-z]/.test(value)) return undefined;
  if (/\d/.test(value) || looksRandom(value, 8) || isKnownSecretValue(value)) return value;
  // `The passphrase is Kettle-Zebra-Quartz-Lamp`: a typed secret need not
  // look random. A single word (`required`) or a short hyphenated phrase
  // (`case-sensitive`) is still prose
  if (connector && typed
    && !/^[A-Za-z][a-z]*$/.test(value) && !(/^[a-z]+(?:-[a-z]+)*$/.test(value) && value.length < 16)) return value;
  // `The passphrase is correcthorsebatterystaple`: one long lowercase word is no prose word
  if (connector && typed && /^[a-z]{16,}$/.test(value)) return value;
  // `Use passcode Quartz-Kettle-Zebra-Lamp-Moon`: with no connector, only a run of three or more capitalised words
  if (typed && /^[A-Z][a-z]+(?:[-_.][A-Z][a-z]+){2,}$/.test(value)) return value;
  return undefined;
}

/**
 * A passphrase written out as words (`The passphrase is correct horse
 * battery staple`, `Passphrase: Correct Horse Battery Staple`): the first
 * word and those after it, up to a prose word or punctuation — three words
 * or more. Its length in `text` from `at`, or 0.
 */
function passphraseRun(text: string, at: number, first: string): number {
  if (!/^[A-Za-z0-9]+$/.test(first) || PROSE_WORDS.has(first.toLowerCase())) return 0;
  const after = PHRASE_WORDS.exec(text.slice(at + first.length, at + first.length + 200))?.[0] ?? '';
  let length = first.length;
  let words = 1;
  for (const m of after.matchAll(/([ \t]+)([A-Za-z0-9]+)/g)) {
    if (PROSE_WORDS.has(m[2].toLowerCase())) break;
    length += m[0].length;
    words++;
  }
  return words >= 3 ? length : 0;
}

/** `text` with credentials written out in prose masked (MCP-034 quotes prose). */
export function maskProseSecrets(text: string): string {
  let out = '';
  let last = 0;
  for (const m of text.matchAll(PROSE_SECRET)) {
    const [match, keyword, connector, plainDq, smartDq, plainSq, smartSq, bare] = m;
    const dq = plainDq ?? smartDq;
    const sq = plainSq ?? smartSq;
    const start = m.index ?? 0;
    if (start < last) continue;
    const run = dq ?? sq ?? bare ?? '';
    const runAt = start + match.lastIndexOf(run);
    // a passphrase is words: the run goes on past the match
    const phrase = bare !== undefined && connector && /^pass ?phrase$/i.test(keyword) ? passphraseRun(text, runAt, bare) : 0;
    if (phrase > 0) {
      out += text.slice(last, runAt) + maskValue(text.slice(runAt, runAt + phrase));
      last = runAt + phrase;
      continue;
    }
    const value = proseSecretValue(run, keyword, connector, dq !== undefined || sq !== undefined);
    if (!value) continue;
    out += text.slice(last, runAt) + maskValue(value);
    last = runAt + value.length;
  }
  out += text.slice(last);
  return out.replace(CREDENTIAL_PAIR, (match: string, value: string) => {
    const pw = value.replace(/[.!?:]+$/, '');
    if (pw.length < 6 || isPlaceholderSecret(pw) || isSecretReference(pw) || pw.includes('…')) return match;
    if (!(/\d/.test(pw) && /[A-Za-z]/.test(pw)) && !looksRandom(pw, 8) && !isKnownSecretValue(pw)) return match;
    const at = match.lastIndexOf(value);
    return `${match.slice(0, at)}${maskValue(pw)}${match.slice(at + pw.length)}`;
  });
}
