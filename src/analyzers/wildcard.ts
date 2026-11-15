/**
 * Glob matching without regular expressions. Globs in scanned configs are
 * attacker-controllable (a repository's project config is enough), and a
 * glob turned into a RegExp (`*` → `.*` / `[^/]*`) backtracks: a pattern of
 * twenty stars against a path takes exponential time. These matchers run in
 * O(pattern × text) at worst and never throw.
 */

type Token =
  | { k: 'star' }
  | { k: 'any' }
  | { k: 'lit'; c: string }
  | { k: 'class'; neg: boolean; ranges: Array<[string, string]> };

/** Longest glob judged; callers decide what a longer one means. */
export const MAX_GLOB_LENGTH = 4096;

function one(t: Token, c: string, ignoreCase: boolean): boolean {
  switch (t.k) {
    case 'any': return true;
    case 'lit': return ignoreCase ? t.c.toLowerCase() === c.toLowerCase() : t.c === c;
    case 'class': {
      const cs = ignoreCase ? [c.toLowerCase(), c.toUpperCase()] : [c];
      const hit = t.ranges.some(([lo, hi]) => cs.some(x => x >= lo && x <= hi));
      return hit !== t.neg;
    }
    default: return false;
  }
}

/**
 * Two-pointer wildcard match: a star matches any run of characters, every
 * other token exactly one. Backtracks only to the last star, so the cost is
 * O(tokens × text).
 */
function matchTokens(toks: Token[], s: string, ignoreCase = false): boolean {
  let ti = 0;
  let si = 0;
  let starT = -1;
  let starS = 0;
  while (si < s.length) {
    const t = toks[ti];
    if (t && t.k === 'star') {
      starT = ti++;
      starS = si;
    } else if (t && one(t, s[si], ignoreCase)) {
      ti++;
      si++;
    } else if (starT >= 0) {
      ti = starT + 1;
      si = ++starS;
    } else {
      return false;
    }
  }
  while (ti < toks.length && toks[ti].k === 'star') ti++;
  return ti === toks.length;
}

/**
 * A simple wildcard pattern against text: `*` matches any run of characters
 * (separators included), `?` one character when `question` is set; every
 * other character is literal.
 */
export function wildcardMatch(pattern: string, text: string, opts: { question?: boolean; ignoreCase?: boolean } = {}): boolean {
  const toks: Token[] = [];
  for (const c of pattern) {
    if (c === '*') {
      if (toks[toks.length - 1]?.k !== 'star') toks.push({ k: 'star' });
    } else if (c === '?' && opts.question) toks.push({ k: 'any' });
    else toks.push({ k: 'lit', c });
  }
  return matchTokens(toks, text, opts.ignoreCase);
}

/** `[...]` at `start`: the class token and the index of its `]`, or
 *  undefined for an unterminated or invalid class (read as a literal `[`). */
function parseClass(glob: string, start: number): { token: Token; end: number } | undefined {
  let i = start + 1;
  let neg = false;
  if (glob[i] === '!' || glob[i] === '^') { neg = true; i++; }
  const ranges: Array<[string, string]> = [];
  let first = true;
  while (i < glob.length && (first || glob[i] !== ']')) {
    first = false;
    let lo = glob[i];
    if (lo === '\\' && i + 1 < glob.length) lo = glob[++i];
    let hi = lo;
    if (glob[i + 1] === '-' && i + 2 < glob.length && glob[i + 2] !== ']') {
      hi = glob[i + 2];
      if (hi === '\\' && i + 3 < glob.length) { hi = glob[i + 3]; i++; }
      i += 2;
      if (hi < lo) return undefined;
    }
    ranges.push([lo, hi]);
    i++;
  }
  if (i >= glob.length) return undefined;
  return { token: { k: 'class', neg, ranges }, end: i };
}

/** One path segment of a glob: `*` and `?` stay inside it, `[...]` is a
 *  character class (`!`/`^` negates), `\x` a literal `x`. */
function segmentTokens(seg: string): Token[] {
  const toks: Token[] = [];
  for (let i = 0; i < seg.length; i++) {
    const c = seg[i];
    if (c === '*') {
      if (toks[toks.length - 1]?.k !== 'star') toks.push({ k: 'star' });
    } else if (c === '?') toks.push({ k: 'any' });
    else if (c === '[') {
      const cls = parseClass(seg, i);
      if (cls) { toks.push(cls.token); i = cls.end; } else toks.push({ k: 'lit', c });
    } else if (c === '\\' && i + 1 < seg.length) toks.push({ k: 'lit', c: seg[++i] });
    else toks.push({ k: 'lit', c });
  }
  return toks;
}

/**
 * A path glob against a path, segment by segment: a segment that is exactly
 * `**` matches any number of segments (zero included), `*` / `?` / `[...]`
 * match within one segment. Consecutive `**` segments collapse. Linear in the
 * product of the two lengths; never throws.
 */
export function pathGlobMatch(glob: string, path: string): boolean {
  const pat: Array<Token[] | null> = [];
  for (const seg of glob.split('/')) {
    if (seg === '**') {
      if (pat[pat.length - 1] !== null || pat.length === 0) pat.push(null);
    } else pat.push(segmentTokens(seg));
  }
  const segs = path.split('/');
  const P = pat.length;
  const S = segs.length;
  // ok[j] for the pattern suffix from i: does pat[i..] match segs[j..]?
  let next = new Array<boolean>(S + 1).fill(false);
  next[S] = true;
  for (let i = P - 1; i >= 0; i--) {
    const cur = new Array<boolean>(S + 1).fill(false);
    const p = pat[i];
    if (p === null) {
      // ** : skip it (next[j]) or consume segment j and stay (cur[j+1])
      for (let j = S; j >= 0; j--) cur[j] = next[j] || (j < S && cur[j + 1]);
    } else {
      for (let j = 0; j < S; j++) cur[j] = next[j + 1] && matchTokens(p, segs[j]);
    }
    next = cur;
  }
  return next[0];
}
