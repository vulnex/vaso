/**
 * Regexes from a scanned config are written for the agent's own engine —
 * Python `re` (Nanobot) or Go RE2 (PicoClaw) — and judged here with a JS
 * RegExp. Syntax the dialects share but JS lacks or reads differently is
 * translated where the meaning carries over exactly:
 *
 * - named groups `(?P<n>…)` → `(?<n>…)`, Python `(?P=n)` → `\k<n>`
 * - `\A` → start of input, Python `\Z` / `\z` (3.14) and Go `\z` → end of
 *   input (lookarounds, so an `m` flag can't widen them)
 * - inline flags: leading groups become RegExp flags; Go's mid-pattern
 *   `(?i)` and scoped `(?i:…)` (Python too) widen `i` to the whole pattern —
 *   an over-approximation, the samples judged are lower-case commands and
 *   paths; `s`, `m` and Go `U` don't change whether a one-line sample matches
 * - Python verbose mode `(?x)`, `(?#…)` comments, `{,n}`
 * - Go `\Q…\E`, `\x{…}`, octal escapes, POSIX classes `[[:alpha:]]`
 * - a `]` first in a class is a literal in both dialects (JS: empty class)
 *
 * What can't be translated is `unsupported` — the caller reports the pattern
 * as not evaluated, never as harmless. What the dialect itself rejects
 * (Go lookarounds and backreferences, Python `(?<n>…)`, unbalanced groups)
 * is `invalid`: the agent refuses the pattern, so it allows nothing.
 */

import type { Evidence } from '../core/types.js';
import { runSamples, type RegexBudget } from './bounded-regex.js';

export type RegexDialect = 'python' | 'go';

export type ForeignRegex =
  | { kind: 'ok'; re: RegExp }
  | { kind: 'invalid' }
  | { kind: 'unsupported' };

/** The longest pattern translated; a longer one is not evaluated. */
const MAX_PATTERN_LENGTH = 8192;

const START = '(?<![\\s\\S])';
const END = '(?![\\s\\S])';

const POSIX_CLASSES: Record<string, string> = {
  alnum: '0-9A-Za-z',
  alpha: 'A-Za-z',
  ascii: '\\x00-\\x7F',
  blank: '\\t ',
  cntrl: '\\x00-\\x1F\\x7F',
  digit: '0-9',
  graph: '!-~',
  lower: 'a-z',
  print: ' -~',
  punct: '!-\\/:-@\\[-`{-~',
  space: '\\t\\n\\v\\f\\r ',
  upper: 'A-Z',
  word: '0-9A-Za-z_',
  xdigit: '0-9A-Fa-f',
};

class Untranslatable extends Error {
  constructor(readonly kind: 'invalid' | 'unsupported') {
    super(kind);
  }
}

const invalid = (): never => { throw new Untranslatable('invalid'); };
const unsupported = (): never => { throw new Untranslatable('unsupported'); };

const escapeLiteral = (c: string): string => (/[\\^$.*+?()[\]{}|/-]/.test(c) ? `\\${c}` : c);

function unit(code: number): string {
  if (code > 0xffff) return unsupported();
  return `\\u${code.toString(16).padStart(4, '0')}`;
}

/** Python accepts flags `aiLmsux`, Go `imsU`. */
function flagLetters(letters: string, dialect: RegexDialect): void {
  const ok = dialect === 'python' ? /^[aiLmsux]*$/ : /^[imsU]*$/;
  if (!ok.test(letters)) invalid();
}

interface Translated { source: string; flags: string }

function translate(pattern: string, dialect: RegexDialect): Translated {
  const py = dialect === 'python';
  const flags = new Set<string>();
  let verbose = false;
  let src = pattern;

  // Leading global flag groups: `(?i)`, `(?is)`, Go `(?i-s)`
  for (let m = /^\(\?([A-Za-z]*)(?:-([A-Za-z]*))?\)/.exec(src); m; m = /^\(\?([A-Za-z]*)(?:-([A-Za-z]*))?\)/.exec(src)) {
    if (py && !m[1] && m[2] === undefined) invalid(); // Python rejects `(?)`, Go reads it as no flags
    flagLetters(m[1], dialect);
    if (m[2] !== undefined) {
      if (py) invalid(); // Python: global flags can't be turned off
      flagLetters(m[2], dialect);
    }
    for (const f of m[1]) {
      if ('ims'.includes(f)) flags.add(f);
      if (f === 'x') verbose = true;
    }
    src = src.slice(m[0].length);
  }

  let out = '';
  let i = 0;
  const n = src.length;

  /** An escape at `i` (pointing at the backslash); returns its JS form and advances. */
  const escape = (inClass: boolean): string => {
    const c = src[i + 1];
    if (c === undefined) return invalid();
    i += 2;
    if (!py && (c === 'p' || c === 'P')) return unsupported();
    if (!py && c === 'x' && src[i] === '{') {
      const close = src.indexOf('}', i);
      const hex = close > 0 ? src.slice(i + 1, close) : '';
      if (!/^[0-9A-Fa-f]{1,8}$/.test(hex)) return invalid();
      i = close + 1;
      return unit(parseInt(hex, 16));
    }
    if (!py && /[0-7]/.test(c)) {
      let digits = c;
      while (digits.length < 3 && /[0-7]/.test(src[i] ?? '')) digits += src[i++];
      if (digits.length === 1 && c !== '0') return invalid(); // `\1`: a backreference, which Go lacks
      return unit(parseInt(digits, 8));
    }
    if (!py && (c === '8' || c === '9')) return invalid();
    if (py && (c === 'N' || c === 'U')) return unsupported();
    if (inClass) {
      if (!py && c === 'Q') return unsupported();
      return `\\${c}`;
    }
    if (c === 'A') return START;
    if (c === 'z') return END;
    if (c === 'Z') return py ? END : invalid();
    if (!py && c === 'C') return invalid(); // RE2 doesn't support \C
    if (!py && c === 'Q') {
      const end = src.indexOf('\\E', i);
      const text = end < 0 ? src.slice(i) : src.slice(i, end);
      i = end < 0 ? n : end + 2;
      return Array.from(text, escapeLiteral).join('');
    }
    return `\\${c}`;
  };

  const charClass = (): string => {
    let cls = '[';
    i++;
    if (src[i] === '^') { cls += '^'; i++; }
    if (src[i] === ']') { cls += '\\]'; i++; }
    for (;;) {
      if (i >= n) return invalid();
      const c = src[i];
      if (c === ']') { i++; return `${cls}]`; }
      if (c === '\\') { cls += escape(true); continue; }
      if (!py && c === '[' && src[i + 1] === ':') {
        const m = /^\[:(\^?)([a-z]+):\]/.exec(src.slice(i, i + 16));
        if (m) {
          if (m[1]) return unsupported();
          const body = POSIX_CLASSES[m[2]];
          if (!body) return invalid();
          cls += body;
          i += m[0].length;
          continue;
        }
      }
      cls += c === '[' ? '\\[' : c;
      i++;
    }
  };

  const group = (): string => {
    const rest = src.slice(i, i + 64);
    if (!rest.startsWith('(?')) { i++; return '('; }
    let m: RegExpExecArray | null;
    if ((m = /^\(\?P<([A-Za-z_]\w*)>/.exec(rest))) { i += m[0].length; return `(?<${m[1]}>`; }
    if ((m = /^\(\?P=([A-Za-z_]\w*)\)/.exec(rest))) {
      if (!py) invalid();
      i += m[0].length;
      return `\\k<${m[1]}>`;
    }
    if (rest.startsWith('(?#')) {
      if (!py) invalid();
      const close = src.indexOf(')', i);
      if (close < 0) invalid();
      i = close + 1;
      return '';
    }
    if (/^\(\?(?:=|!|<=|<!)/.test(rest)) {
      if (!py) invalid(); // RE2 has no lookarounds
      const len = rest[2] === '<' ? 4 : 3;
      i += len;
      return rest.slice(0, len);
    }
    if ((m = /^\(\?<([A-Za-z_]\w*)>/.exec(rest))) {
      if (py) invalid(); // Python spells it (?P<name>)
      i += m[0].length;
      return m[0];
    }
    if ((m = /^\(\?([A-Za-z]*)(?:-([A-Za-z]*))?([:)])/.exec(rest))) {
      flagLetters(m[1], dialect);
      if (m[2] !== undefined) flagLetters(m[2], dialect);
      if (m[3] === ')') {
        if (py && !m[1] && m[2] === undefined) invalid(); // Python rejects `(?)`
        if (py) invalid(); // Python 3.11+: global flags only at the start
      } else if (py && m[1].includes('x')) {
        unsupported();
      }
      if (m[1].includes('i')) flags.add('i');
      i += m[0].length;
      return m[3] === ':' ? '(?:' : '';
    }
    if (!py && /^\(\?[>(]/.test(rest)) invalid();
    // anything else (a (?(1)…) conditional): JS can't run it
    i += 2;
    return '(?';
  };

  // Python 3.11 atomic groups `(?>X)` and possessive quantifiers `X*+` run as
  // `(?=(?<g>X))\k<g>`: the lookahead's match is taken whole, never given back
  const open: Array<{ start: number; atomic: boolean }> = [];
  let atomStart = -1; // where in `out` the last atom began
  let quantified = false; // the last token was a quantifier
  let atomics = 0;
  const atomic = (body: string) => `(?=(?<vasoAtomic${atomics}>${body}))\\k<vasoAtomic${atomics++}>`;

  while (i < n) {
    const c = src[i];
    if (verbose && /\s/.test(c)) { i++; continue; }
    if (verbose && c === '#') {
      while (i < n && src[i] !== '\n') i++;
      continue;
    }
    if (c === '(') {
      const start = out.length;
      quantified = false;
      if (py && src.startsWith('(?>', i)) {
        i += 3;
        open.push({ start, atomic: true });
        out += '(?:';
        continue;
      }
      const text = group();
      out += text;
      if (text.startsWith('(')) open.push({ start, atomic: false });
      else if (text) atomStart = start; // a backreference
      continue;
    }
    if (c === ')') {
      const g = open.pop();
      out += ')';
      i++;
      if (g?.atomic) out = out.slice(0, g.start) + atomic(out.slice(g.start));
      atomStart = g ? g.start : -1;
      quantified = false;
      continue;
    }
    if (c === '|') {
      out += c;
      i++;
      atomStart = -1;
      quantified = false;
      continue;
    }
    const brace = c === '{' ? /^\{(?:\d+(?:,\d*)?|,(\d+))\}/.exec(src.slice(i, i + 32)) : null;
    if (c === '*' || c === '+' || c === '?' || (brace && (py || brace[1] === undefined))) {
      if (quantified && c === '+' && py && atomStart >= 0) {
        out = out.slice(0, atomStart) + atomic(out.slice(atomStart));
        i++;
        quantified = false;
        continue;
      }
      if (quantified && c === '?') {
        out += '?'; // lazy
        i++;
        quantified = false;
        continue;
      }
      if (brace) {
        out += brace[1] !== undefined ? `{0,${brace[1]}}` : brace[0]; // Python `{,n}`
        i += brace[0].length;
      } else {
        out += c;
        i++;
      }
      quantified = true;
      continue;
    }
    atomStart = out.length;
    quantified = false;
    if (c === '\\') out += escape(false);
    else if (c === '[') out += charClass();
    else {
      out += c;
      i++;
    }
  }
  // the inserted groups would renumber the pattern's own backreferences
  if (atomics > 0 && /\\[1-9]/.test(out)) unsupported();
  return { source: out, flags: [...flags].sort().join('') };
}

/**
 * Faults every dialect rejects: an unbalanced group, an unterminated class,
 * a trailing backslash, a quantifier with nothing to repeat; in Go also a
 * repeated repetition (`a**`, Python's possessive `a*+`).
 */
function structurallyInvalid(pattern: string, dialect: RegexDialect): boolean {
  let depth = 0;
  let prevAtom = false; // the previous token can take a quantifier
  let prevQuant = false;
  for (let i = 0; i < pattern.length; i++) {
    const c = pattern[i];
    if (c === '\\') {
      if (i + 1 >= pattern.length) return true;
      i++;
      prevAtom = true;
      prevQuant = false;
      continue;
    }
    if (c === '[') {
      let j = i + 1;
      if (pattern[j] === '^') j++;
      if (pattern[j] === ']') j++;
      while (j < pattern.length && pattern[j] !== ']') j += pattern[j] === '\\' ? 2 : 1;
      if (j >= pattern.length) return true;
      i = j;
      prevAtom = true;
      prevQuant = false;
      continue;
    }
    if (c === '(') { depth++; prevAtom = false; prevQuant = false; continue; }
    if (c === ')') {
      if (--depth < 0) return true;
      prevAtom = true;
      prevQuant = false;
      continue;
    }
    if (c === '|') { prevAtom = false; prevQuant = false; continue; }
    if (c === '*' || c === '+' || c === '?') {
      if (prevQuant) {
        // `*?` lazy is fine everywhere; Python 3.11 also takes `*+`
        if (c === '?' || (c === '+' && dialect === 'python')) { prevQuant = false; prevAtom = false; continue; }
        return true;
      }
      if (!prevAtom && !(c === '?' && pattern[i - 1] === '(')) return true;
      prevQuant = true;
      prevAtom = false;
      continue;
    }
    prevAtom = true;
    prevQuant = false;
  }
  return depth !== 0;
}

/**
 * A config regex as a JS RegExp: `fullmatch` anchors it to the whole text
 * (Python `re.fullmatch`), otherwise it searches (Go `MatchString`). The
 * RegExp comes from config: run it with `testSamples`, never `re.test`.
 */
export function compileForeignRegex(pattern: string, dialect: RegexDialect, opts: { fullmatch?: boolean } = {}): ForeignRegex {
  if (pattern.length > MAX_PATTERN_LENGTH) return { kind: 'unsupported' };
  let t: Translated;
  try {
    t = translate(pattern, dialect);
  } catch (e) {
    if (e instanceof Untranslatable) return { kind: e.kind };
    throw e;
  }
  try {
    return { kind: 'ok', re: new RegExp(opts.fullmatch ? `^(?:${t.source})$` : t.source, t.flags) };
  } catch {
    return { kind: structurallyInvalid(pattern, dialect) ? 'invalid' : 'unsupported' };
  }
}

/** Why a pattern's verdict is unknown: it ran out of time, the check's
 *  regex budget was spent before it ran, or its syntax can't be run here. */
export type NotEvaluated = 'timeout' | 'budget' | 'unsupported';

/**
 * Whether a config regex matches every sample: `catch-all`, a NotEvaluated
 * reason, or undefined (it misses one, or the dialect rejects it). Samples
 * go shortest first (`untilMiss`).
 */
export function judgeCatchAll(
  pattern: string,
  dialect: RegexDialect,
  samples: readonly string[],
  opts: { fullmatch?: boolean; budget?: RegexBudget } = {},
): 'catch-all' | NotEvaluated | undefined {
  const c = compileForeignRegex(pattern, dialect, { fullmatch: opts.fullmatch });
  if (c.kind === 'invalid') return undefined;
  if (c.kind === 'unsupported') return 'unsupported';
  const run = runSamples(c.re, samples, { untilMiss: true, budget: opts.budget });
  if (run.hits.every(Boolean)) return 'catch-all';
  return run.complete ? undefined : run.reason;
}

/** Evidence detail for a pattern not evaluated; `what` completes "whether it …". */
export function notEvaluatedDetail(reason: NotEvaluated, what: string): string {
  switch (reason) {
    case 'unsupported':
      return `Pattern not evaluated: VASO cannot translate its regex syntax, so whether it ${what} is unknown — review it`;
    case 'budget':
      return `Pattern not evaluated: the time for judging slow patterns in this check was spent, so whether it ${what} is unknown — review it`;
    default:
      return `Pattern not evaluated: it backtracks exponentially on sample inputs, so whether it ${what} is unknown — review it`;
  }
}

/**
 * One evidence item for the patterns of `key` left unrun once the check's
 * regex budget was spent (a config can list hundreds); `what` completes
 * "whether they …".
 */
export function unjudgedEvidence(file: string, key: string, patterns: readonly string[], what: string): Evidence {
  const n = patterns.length;
  return {
    file,
    snippet: `${key}: ${JSON.stringify(patterns[0])}${n > 1 ? ` (and ${n - 1} more)` : ''}`,
    detail: `${n} pattern${n === 1 ? '' : 's'} not evaluated: the time for judging slow patterns in this check was spent, so whether ${n === 1 ? 'it' : 'they'} ${what} is unknown — review ${n === 1 ? 'it' : 'them'}`,
  };
}
