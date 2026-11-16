/**
 * Regexes from a scanned config are written for the agent's own engine —
 * Python `re` (Nanobot) or Go RE2 (PicoClaw) — and judged here with a JS
 * RegExp. Syntax the dialects share but JS lacks or reads differently is
 * translated where the meaning carries over exactly:
 *
 * - named groups `(?P<n>…)` → `(?<n>…)`, Python `(?P=n)` → `\k<n>` (Go has
 *   no backreferences, so its names are dropped — Go allows a name twice)
 * - `\A` → start of input, Python `\Z` / `\z` (3.14) and Go `\z` → end of
 *   input (lookarounds, so an `m` flag can't widen them)
 * - inline flags, leading, mid-pattern (Go) and scoped `(?i:…)`, each over
 *   the part of the pattern it governs: case-insensitivity is spelled out
 *   (every cased letter becomes a class of its case variants), so a scoped
 *   `(?i)` doesn't widen to the rest of the pattern; `s`, `m` and Go `U`
 *   don't change whether a one-line sample matches
 * - Python verbose mode `(?x)` / `(?x:…)`, `(?#…)` comments, `{,n}`, `{,}`
 * - Go `\Q…\E`, `\x{…}`, octal escapes, POSIX classes `[[:alpha:]]` and
 *   `[[:^alpha:]]`, Unicode classes `\pL`, `\p{Greek}`, `\P{…}` (JS `u` flag)
 * - a `]` first in a class is a literal in both dialects (JS: empty class)
 *
 * What can't be translated is `unsupported` — the caller reports the pattern
 * as not evaluated, never as harmless. What the dialect itself rejects is
 * `invalid`: the agent refuses the pattern, so it allows nothing. Each
 * dialect's own rules apply: unknown escapes (`\e`, `\y`), Go lookarounds and
 * backreferences, Python `(?<n>…)`, `(?L)` and mid-pattern flags, repeat
 * counts over Go's 1000 or Python's 2³²−2, `{3,2}`, a repeated repetition,
 * unbalanced groups.
 */

import type { Evidence } from '../core/types.js';
import { runSampleBatch, type RegexBudget, type SampleJob } from './bounded-regex.js';

export type RegexDialect = 'python' | 'go';

export type ForeignRegex =
  | { kind: 'ok'; re: RegExp }
  | { kind: 'invalid' }
  | { kind: 'unsupported' };

/** The longest pattern translated; a longer one is not evaluated. */
const MAX_PATTERN_LENGTH = 8192;

const START = '(?<![\\s\\S])';
const END = '(?![\\s\\S])';

type Range = [number, number];

const POSIX_CLASSES: Record<string, Range[]> = {
  alnum: [[0x30, 0x39], [0x41, 0x5a], [0x61, 0x7a]],
  alpha: [[0x41, 0x5a], [0x61, 0x7a]],
  ascii: [[0x00, 0x7f]],
  blank: [[0x09, 0x09], [0x20, 0x20]],
  cntrl: [[0x00, 0x1f], [0x7f, 0x7f]],
  digit: [[0x30, 0x39]],
  graph: [[0x21, 0x7e]],
  lower: [[0x61, 0x7a]],
  print: [[0x20, 0x7e]],
  punct: [[0x21, 0x2f], [0x3a, 0x40], [0x5b, 0x60], [0x7b, 0x7e]],
  space: [[0x09, 0x0d], [0x20, 0x20]],
  upper: [[0x41, 0x5a]],
  word: [[0x30, 0x39], [0x41, 0x5a], [0x5f, 0x5f], [0x61, 0x7a]],
  xdigit: [[0x30, 0x39], [0x41, 0x46], [0x61, 0x66]],
};

/** Single-character escapes both dialects share. */
const CONTROL_ESCAPES: Record<string, number> = { a: 0x07, f: 0x0c, n: 0x0a, r: 0x0d, t: 0x09, v: 0x0b };

/** Python's MAXREPEAT: a repeat count at or above it is rejected. */
const PY_MAXREPEAT = 4294967295;
/** RE2's largest repeat count. */
const GO_MAXREPEAT = 1000;

class Untranslatable extends Error {
  constructor(readonly kind: 'invalid' | 'unsupported') {
    super(kind);
  }
}

const invalid = (): never => { throw new Untranslatable('invalid'); };
const unsupported = (): never => { throw new Untranslatable('unsupported'); };

/** A code unit as JS regex source, valid with and without the `u` flag. */
function hex(code: number): string {
  if (code > 0xffff) return unsupported();
  if (/[0-9A-Za-z]/.test(String.fromCharCode(code))) return String.fromCharCode(code);
  return `\\u${code.toString(16).padStart(4, '0')}`;
}

const rangeText = ([lo, hi]: Range): string => (lo === hi ? hex(lo) : `${hex(lo)}-${hex(hi)}`);

let caseOrbits: Map<number, number[]> | undefined;

/**
 * For each BMP code unit with case variants, the others it matches when
 * case-insensitive (closed over upper/lower mappings, so k ~ K ~ U+212A).
 */
function caseVariants(): Map<number, number[]> {
  if (caseOrbits) return caseOrbits;
  const parent = new Int32Array(0x10000).map((_, k) => k);
  const root = (x: number): number => {
    while (parent[x] !== x) x = parent[x] = parent[parent[x]];
    return x;
  };
  for (let c = 0; c <= 0xffff; c++) {
    if (c >= 0xd800 && c <= 0xdfff) continue;
    const ch = String.fromCharCode(c);
    for (const v of [ch.toLowerCase(), ch.toUpperCase()]) {
      if (v.length === 1) parent[root(c)] = root(v.charCodeAt(0));
    }
  }
  const orbits = new Map<number, number[]>();
  for (let c = 0; c <= 0xffff; c++) {
    const r = root(c);
    const list = orbits.get(r);
    if (list) list.push(c);
    else orbits.set(r, [c]);
  }
  caseOrbits = new Map();
  for (const members of orbits.values()) {
    if (members.length < 2) continue;
    for (const c of members) caseOrbits.set(c, members.filter(m => m !== c));
  }
  return caseOrbits;
}

/** `ranges` plus the case variants of every code unit in them. */
function foldRanges(ranges: readonly Range[]): Range[] {
  const variants = caseVariants();
  const extra: Range[] = [];
  for (const [lo, hi] of ranges) {
    if (hi - lo <= 4096) {
      for (let c = lo; c <= hi; c++) for (const v of variants.get(c) ?? []) extra.push([v, v]);
    } else {
      for (const [c, vs] of variants) if (c >= lo && c <= hi) for (const v of vs) extra.push([v, v]);
    }
  }
  return [...ranges, ...extra];
}

/** A literal code unit, as a class of its case variants when case-insensitive. */
function literal(code: number, ci: boolean): string {
  const variants = ci ? caseVariants().get(code) : undefined;
  return variants ? `[${[code, ...variants].map(hex).join('')}]` : hex(code);
}

/** Python accepts flags `aimsux` (`L` only on bytes patterns), Go `imsU`; a `-` needs flags after it. */
function flagLetters(on: string, off: string | undefined, dialect: RegexDialect): void {
  if (dialect === 'python') {
    if (!/^[aimsux]*$/.test(on) || (on.includes('a') && on.includes('u'))) invalid();
    if (off !== undefined && !/^[imsx]+$/.test(off)) invalid();
  } else {
    if (!/^[imsU]*$/.test(on)) invalid();
    if (off !== undefined && !/^[imsU]+$/.test(off)) invalid();
  }
}

interface Mode { ci: boolean; verbose: boolean }

function withFlags(mode: Mode, on: string, off: string | undefined): Mode {
  return {
    ci: off?.includes('i') ? false : on.includes('i') || mode.ci,
    verbose: off?.includes('x') ? false : on.includes('x') || mode.verbose,
  };
}

interface Translated { source: string; flags: string }

/** An escape: one code unit, a set usable in a class, or other source (anchors, backreferences, quoted runs). */
type Atom = { code: number } | { set: string; unicode?: boolean } | { raw: string; anchor?: boolean };

function translate(pattern: string, dialect: RegexDialect): Translated {
  const py = dialect === 'python';
  const flags = new Set<string>();
  let mode: Mode = { ci: false, verbose: false };
  let src = pattern;

  const LEADING = /^\(\?([A-Za-z]*)(?:-([A-Za-z]*))?\)/;
  for (let m = LEADING.exec(src); m; m = LEADING.exec(src)) {
    if (py && !m[1] && m[2] === undefined) invalid(); // Python rejects `(?)`, Go reads it as no flags
    if (py && m[2] !== undefined) invalid(); // Python: global flags can't be turned off
    flagLetters(m[1], m[2], dialect);
    for (const f of m[1]) if (f === 's' || f === 'm') flags.add(f);
    mode = withFlags(mode, m[1], m[2]);
    src = src.slice(m[0].length);
  }

  let out = '';
  let i = 0;
  const n = src.length;
  let groups = 0; // capturing groups opened
  const closed = new Set<number>();
  const names = new Map<string, number>();
  let unicode = false; // a Unicode class needs the JS `u` flag

  const fixedHex = (len: number): number => {
    const digits = src.slice(i, i + len);
    if (!new RegExp(`^[0-9A-Fa-f]{${len}}$`).test(digits)) invalid();
    i += len;
    return parseInt(digits, 16);
  };

  const unicodeClass = (negated: boolean): Atom => {
    let name: string;
    if (src[i] === '{') {
      const close = src.indexOf('}', i);
      if (close < 0) invalid();
      name = src.slice(i + 1, close);
      i = close + 1;
    } else {
      name = src[i] ?? '';
      i++;
    }
    if (name.startsWith('^')) {
      negated = !negated;
      name = name.slice(1);
    }
    let js: string;
    if (name === 'Any' || /^[CLMNPSZ][a-z]?$/.test(name)) js = name;
    else if (name.length > 1 && /^[A-Za-z_]+$/.test(name)) js = `Script=${name}`;
    else return invalid();
    const text = `\\${negated ? 'P' : 'p'}{${js}}`;
    try {
      new RegExp(text, 'u');
    } catch {
      return unsupported(); // a name Go may know and this Node doesn't
    }
    unicode = true;
    return { set: text, unicode: true };
  };

  const octal = (first: string, max: number): number => {
    let digits = first;
    while (digits.length < max && /[0-7]/.test(src[i] ?? '')) digits += src[i++];
    const code = parseInt(digits, 8);
    if (code > 0o377) invalid();
    return code;
  };

  /** An escape at `i` (pointing at the backslash); advances past it. */
  const escape = (inClass: boolean): Atom => {
    const c = src[i + 1];
    if (c === undefined) return invalid();
    i += 2;
    if ('dDsSwW'.includes(c)) return { set: `\\${c}` };
    if (c in CONTROL_ESCAPES) return { code: CONTROL_ESCAPES[c] };
    if (!py && (c === 'p' || c === 'P')) return unicodeClass(c === 'P');
    if (c === 'x') {
      if (!py && src[i] === '{') {
        const close = src.indexOf('}', i);
        const digits = close > 0 ? src.slice(i + 1, close) : '';
        if (!/^[0-9A-Fa-f]{1,8}$/.test(digits) || parseInt(digits, 16) > 0x10ffff) invalid();
        i = close + 1;
        return { code: parseInt(digits, 16) };
      }
      return { code: fixedHex(2) };
    }
    if (py && c === 'u') return { code: fixedHex(4) };
    if (py && c === 'U') {
      const code = fixedHex(8);
      if (code > 0x10ffff) invalid();
      return { code };
    }
    if (py && c === 'N') return src[i] === '{' ? unsupported() : invalid(); // a Unicode character name
    if (/[0-9]/.test(c)) {
      if (!py) {
        // `\0`, or `\1`–`\7` followed by another octal digit; `\1` alone is a backreference
        if (c === '0' || (/[1-7]/.test(c) && /[0-7]/.test(src[i] ?? ''))) return { code: octal(c, 3) };
        return invalid();
      }
      if (c === '0') return { code: octal(c, 3) };
      if (inClass) return /[0-7]/.test(c) ? { code: octal(c, 3) } : invalid();
      let digits = c;
      if (/[0-9]/.test(src[i] ?? '')) {
        digits += src[i++];
        if (/^[0-7]{2}$/.test(digits) && /[0-7]/.test(src[i] ?? '')) return { code: octal(digits, 3) };
      }
      const g = Number(digits);
      if (!closed.has(g)) invalid(); // undefined or still open
      if (mode.ci) unsupported(); // a case-insensitive backreference
      return { raw: `(?:\\${g})` };
    }
    if (inClass) {
      if (py && c === 'b') return { code: 0x08 };
      if (!py && c === 'Q') unsupported();
    } else {
      if (c === 'A') return { raw: START, anchor: true };
      if (c === 'z') return { raw: END, anchor: true };
      if (c === 'Z' && py) return { raw: END, anchor: true };
      if (c === 'b' || c === 'B') return { raw: `\\${c}`, anchor: true };
      if (!py && c === 'Q') {
        const end = src.indexOf('\\E', i);
        const text = end < 0 ? src.slice(i) : src.slice(i, end);
        i = end < 0 ? n : end + 2;
        return { raw: Array.from({ length: text.length }, (_, k) => literal(text.charCodeAt(k), mode.ci)).join('') };
      }
    }
    if (/[A-Za-z0-9]/.test(c)) return invalid(); // an escape the dialect doesn't define
    const code = c.charCodeAt(0);
    if (code > 0x7f && !py) return invalid(); // RE2 escapes only ASCII punctuation
    return { code };
  };

  const classAtom = (): { code: number } | { set: string; unicode?: boolean } => {
    if (src[i] === '\\') {
      const e = escape(true);
      if ('raw' in e) return invalid();
      return e;
    }
    return { code: src.charCodeAt(i++) };
  };

  const charClass = (): string => {
    i++;
    let negate = false;
    if (src[i] === '^') { negate = true; i++; }
    let ranges: Range[] = [];
    const sets: string[] = [];
    const negPosix: Range[][] = [];
    let unicodeSet = false;
    for (let first = true; ; first = false) {
      if (i >= n) return invalid();
      if (src[i] === ']' && !first) { i++; break; }
      if (!py && src[i] === '[' && src[i + 1] === ':') {
        const m = /^\[:(\^?)([a-z]+):\]/.exec(src.slice(i, i + 16));
        if (m) {
          const body = POSIX_CLASSES[m[2]];
          if (!body) return invalid();
          if (m[1]) negPosix.push(body);
          else ranges.push(...body);
          i += m[0].length;
          continue;
        }
      }
      const lo = classAtom();
      if ('set' in lo) {
        sets.push(lo.set);
        unicodeSet ||= !!lo.unicode;
        if (py && src[i] === '-' && i + 1 < n && src[i + 1] !== ']') invalid(); // bad character range
        continue;
      }
      if (src[i] === '-' && i + 1 < n && src[i + 1] !== ']') {
        i++;
        const hi = classAtom();
        if (!('code' in hi) || hi.code < lo.code) return invalid();
        ranges.push([lo.code, hi.code]);
      } else {
        ranges.push([lo.code, lo.code]);
      }
    }
    if (mode.ci) {
      if (unicodeSet || negPosix.length > 0) unsupported();
      ranges = foldRanges(ranges);
    }
    const body = ranges.map(rangeText).join('') + sets.join('');
    if (negPosix.length === 0) return `[${negate ? '^' : ''}${body}]`;
    const posix = negPosix.map(r => r.map(rangeText).join(''));
    if (!negate) return `(?:${[...(body ? [`[${body}]`] : []), ...posix.map(p => `[^${p}]`)].join('|')})`;
    // not (body or not-P1 or …) = not body, and P1, and …
    const last = posix.pop()!;
    return `(?:${body ? `(?![${body}])` : ''}${posix.map(p => `(?=[${p}])`).join('')}[${last}])`;
  };

  /** A `{…}` repeat at `i` as JS source, or undefined when the dialect reads the brace literally. */
  const repeat = (): { text: string; length: number; factor: number } | undefined => {
    const m = (py ? /^\{(\d*)(,?)(\d*)\}/ : /^\{(\d+)(,?)(\d*)\}/).exec(src.slice(i, i + 48));
    if (!m || (!m[1] && !m[2])) return undefined; // Python `{}` is literal
    const lo = m[1] ? Number(m[1]) : 0;
    const hi = m[2] ? (m[3] ? Number(m[3]) : undefined) : lo;
    if (py ? lo >= PY_MAXREPEAT || (hi ?? 0) >= PY_MAXREPEAT : lo > GO_MAXREPEAT || (hi ?? 0) > GO_MAXREPEAT) invalid();
    if (hi !== undefined && hi < lo) invalid();
    return {
      text: hi === undefined ? `{${lo},}` : m[2] ? `{${lo},${hi}}` : `{${lo}}`,
      length: m[0].length,
      factor: Math.max(1, hi ?? lo),
    };
  };

  type Group = { start: number; atomic: boolean; saved: Mode; capture?: number };
  const open: Group[] = [];
  // RE2 caps nested `{n}` repeats too: the product along any nesting chain
  // must stay within 1000. Per open group: the largest product inside it.
  const nested: number[] = [1];
  let lastNested = 1; // … of the last atom
  const push = (g: Group) => {
    open.push(g);
    nested.push(1);
  };
  let atomStart = -1; // where in `out` the last atom began
  let canRepeat = false; // the last token takes a quantifier
  let quantified = false; // the last token was a quantifier
  let modified = false; // … already made lazy or possessive
  let atomics = 0;
  const atomic = (body: string) => `(?=(?<vasoAtomic${atomics}>${body}))\\k<vasoAtomic${atomics++}>`;
  const atom = () => {
    lastNested = 1;
    atomStart = out.length;
    canRepeat = true;
    quantified = false;
  };

  while (i < n) {
    const c = src[i];
    if (mode.verbose && /\s/.test(c)) { i++; continue; }
    if (mode.verbose && c === '#') {
      while (i < n && src[i] !== '\n') i++;
      continue;
    }
    if (c === '(') {
      const rest = src.slice(i, i + 64);
      const start = out.length;
      let m: RegExpExecArray | null;
      if (rest.startsWith('(?#')) {
        if (!py) invalid();
        const close = src.indexOf(')', i);
        if (close < 0) invalid();
        i = close + 1;
        continue;
      }
      if ((m = /^\(\?P=([A-Za-z_]\w*)\)/.exec(rest))) {
        if (!py) invalid();
        const g = names.get(m[1]);
        if (g === undefined || !closed.has(g)) invalid();
        if (mode.ci) unsupported(); // a case-insensitive backreference
        atom();
        out += `\\k<${m[1]}>`;
        i += m[0].length;
        continue;
      }
      canRepeat = false;
      quantified = false;
      if (!rest.startsWith('(?')) {
        push({ start, atomic: false, saved: mode, capture: ++groups });
        out += '(';
        i++;
        continue;
      }
      if (py && rest.startsWith('(?>')) {
        push({ start, atomic: true, saved: mode });
        out += '(?:';
        i += 3;
        continue;
      }
      if ((m = /^\(\?(?:=|!|<=|<!)/.exec(rest))) {
        if (!py) invalid(); // RE2 has no lookarounds
        push({ start, atomic: false, saved: mode });
        out += m[0];
        i += m[0].length;
        continue;
      }
      if (py && rest.startsWith('(?<')) invalid(); // Python spells it (?P<name>)
      if ((m = py ? /^\(\?P<([A-Za-z_]\w*)>/.exec(rest) : /^\(\?P?<(\w+)>/.exec(rest))) {
        if (py && names.has(m[1])) invalid(); // a name defined twice
        const g = ++groups;
        if (py) names.set(m[1], g);
        push({ start, atomic: false, saved: mode, capture: g });
        out += py ? `(?<${m[1]}>` : '(';
        i += m[0].length;
        continue;
      }
      if ((m = /^\(\?([A-Za-z]*)(?:-([A-Za-z]*))?([:)])/.exec(rest))) {
        flagLetters(m[1], m[2], dialect);
        i += m[0].length;
        if (m[3] === ')') {
          if (py) invalid(); // Python 3.11+: global flags only at the start
          mode = withFlags(mode, m[1], m[2]); // Go: to the end of the enclosing group
          continue;
        }
        push({ start, atomic: false, saved: mode });
        mode = withFlags(mode, m[1], m[2]);
        out += '(?:';
        continue;
      }
      if (!py && /^\(\?[>(]/.test(rest)) invalid();
      push({ start, atomic: false, saved: mode });
      out += '(?';
      i += 2;
      continue;
    }
    if (c === ')') {
      const g = open.pop();
      if (!g) return invalid();
      lastNested = nested.pop()!;
      nested[nested.length - 1] = Math.max(nested[nested.length - 1], lastNested);
      out += ')';
      i++;
      if (g.atomic) out = out.slice(0, g.start) + atomic(out.slice(g.start));
      if (g.capture !== undefined) closed.add(g.capture);
      mode = g.saved;
      atomStart = g.start;
      canRepeat = true;
      quantified = false;
      continue;
    }
    if (c === '|') {
      out += c;
      i++;
      atomStart = -1;
      canRepeat = false;
      quantified = false;
      continue;
    }
    const brace = c === '{' ? repeat() : undefined;
    if (c === '*' || c === '+' || c === '?' || brace) {
      if (quantified) {
        if (c === '?' && !modified) {
          out += '?'; // lazy
          i++;
          modified = true;
          continue;
        }
        if (c === '+' && py && !modified && atomStart >= 0) {
          out = out.slice(0, atomStart) + atomic(out.slice(atomStart)); // possessive
          i++;
          modified = true;
          continue;
        }
        invalid(); // a repeated repetition
      }
      if (!canRepeat) invalid(); // nothing to repeat
      if (brace) {
        const chain = brace.factor * lastNested;
        if (!py && chain > GO_MAXREPEAT) invalid();
        nested[nested.length - 1] = Math.max(nested[nested.length - 1], chain);
        out += brace.text;
        i += brace.length;
      } else {
        out += c;
        i++;
      }
      quantified = true;
      modified = false;
      canRepeat = false;
      continue;
    }
    if (c === '\\') {
      const e = escape(false);
      atom();
      if ('code' in e) out += literal(e.code, mode.ci);
      else if ('set' in e) {
        if (e.unicode && mode.ci) unsupported(); // case-folded Unicode classes
        out += e.set;
      } else if (e.anchor) {
        // Python can't repeat an anchor; RE2 can (an empty-width repeat)
        if (py) canRepeat = false;
        out += py ? e.raw : `(?:${e.raw})`;
      } else out += e.raw;
      continue;
    }
    atom();
    if (c === '[') out += charClass();
    else if (c === '^' || c === '$') {
      if (py) canRepeat = false;
      out += py ? c : `(?:${c})`;
      i++;
    } else if (c === '.') {
      out += c;
      i++;
    } else {
      out += literal(src.charCodeAt(i), mode.ci);
      i++;
    }
  }
  if (open.length > 0) invalid();
  // the inserted groups would renumber the pattern's own backreferences
  if (atomics > 0 && /\\[1-9]/.test(out)) unsupported();
  if (unicode) flags.add('u');
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
 * For each config regex, whether it matches every sample: `catch-all`, a
 * NotEvaluated reason, or undefined (it misses one, or the dialect rejects
 * it). Samples go shortest first (`untilMiss`). The patterns of one list are
 * judged together (`runSampleBatch`): each gets a first slice of its own, so
 * slow patterns listed before a catch-all can't use up the time it needs.
 */
export function judgeCatchAlls(
  patterns: readonly string[],
  dialect: RegexDialect,
  samples: readonly string[],
  opts: { fullmatch?: boolean; budget?: RegexBudget } = {},
): Array<'catch-all' | NotEvaluated | undefined> {
  const compiled = patterns.map(p => compileForeignRegex(p, dialect, { fullmatch: opts.fullmatch }));
  const out: Array<'catch-all' | NotEvaluated | undefined> = compiled.map(c => (c.kind === 'unsupported' ? 'unsupported' : undefined));
  const jobs: SampleJob[] = [];
  const at: number[] = [];
  compiled.forEach((c, k) => {
    if (c.kind !== 'ok') return;
    jobs.push({ re: c.re, samples, untilMiss: true });
    at.push(k);
  });
  runSampleBatch(jobs, { budget: opts.budget }).forEach((run, j) => {
    out[at[j]] = run.hits.every(Boolean) ? 'catch-all' : run.complete ? undefined : run.reason;
  });
  return out;
}

/** `judgeCatchAlls` for one pattern. */
export function judgeCatchAll(
  pattern: string,
  dialect: RegexDialect,
  samples: readonly string[],
  opts: { fullmatch?: boolean; budget?: RegexBudget } = {},
): 'catch-all' | NotEvaluated | undefined {
  return judgeCatchAlls([pattern], dialect, samples, opts)[0];
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
 * "whether it …" (singular verb).
 */
export function unjudgedEvidence(file: string, key: string, patterns: readonly string[], what: string): Evidence {
  const n = patterns.length;
  return {
    file,
    snippet: `${key}: ${JSON.stringify(patterns[0])}${n > 1 ? ` (and ${n - 1} more)` : ''}`,
    detail: `${n} pattern${n === 1 ? '' : 's'} not evaluated: the time for judging slow patterns in this check was spent, so whether ${n === 1 ? 'it' : 'any of them'} ${what} is unknown — review ${n === 1 ? 'it' : 'them'}`,
  };
}
