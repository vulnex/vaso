/**
 * Static screen for declarative-rule regexes that can backtrack
 * super-linearly. Rules come from files a scan picks up (a repository's
 * `.vaso/rules/` included), and a rule like `(a+)+$` used to hang a scan on a
 * 41-character config line. JavaScript's engine backtracks: a failing
 * search tries every start position and, from each, every way the pattern
 * can match. The pattern is turned into an NFA and judged on its ambiguity
 * (`backtrackingReason`):
 *
 *   - exponential — a state with two different loops reading the same text
 *     (`(a+)+`, `(a|aa)+`, `(\w|\d)+`): rejected;
 *   - polynomial — a chain of loops where each can read the text of the
 *     next (`.*a.*a.*b`, `\d+\d+`). The search over start positions is one
 *     more such loop, unless the pattern is anchored with `^`. A chain of k
 *     loops costs about n^k steps; rule input is capped at MAX_RULE_INPUT
 *     (4096) characters, so two (16M steps) is fine and three (`.*.*=`,
 *     `\d+\d+x` unanchored: ~10 s) is rejected. A loop reached only once the
 *     pattern has already matched (`.*password.*`) doesn't count: the
 *     search stops there;
 *   - finite — bounded repeats and optional groups that can split the same
 *     text many ways (`(a{1,4}){4}(a{1,4}){4}`, `(a|a)?(a|a)?…`): rejected
 *     above MAX_SPLITS ways. A bounded repeat with a wide range
 *     (`{0,100}`) is judged as the unbounded loop it behaves like.
 *
 * A lookahead body backtracks from every place it runs, so it is part of
 * the NFA (a branch that ends nowhere): `.+(?=.*=)` costs what `.+.*=` does.
 * A lookbehind body runs right to left and is judged on its own, its cost
 * multiplied by how often the pattern gets there. A backreference is a copy
 * of its group (`(.*)\1x` is `(.*)(?:.*)x`). The source is read the way V8
 * reads it without the `u` flag: `[^]`, `[]`, `\c` without a letter, `\8`,
 * octal escapes, `\k` without named groups.
 *
 * Patterns the parser can't follow, or too large to analyse, are rejected.
 */

/** Longest text (one line, one config value) a rule regex is run on. */
export const MAX_RULE_INPUT = 4096;

/**
 * Longest a pattern rule may spend matching in one check run (all lines of
 * all its files). An accepted pattern can still cost n^2 per line: ~16 ms on
 * a 4 KB line, so seconds on a megabyte file and more on a skill tree.
 */
export const MAX_RULE_SCAN_MS = 5_000;

/**
 * Longest all rules together may spend matching on one host in one scan: a
 * cloned repository's `.vaso/rules/` can hold many rules, each within its
 * own budget, and the scan runs them for every agent.
 */
export const MAX_RULES_SCAN_MS = 15_000;

interface Term {
  /** single-character atom (literal, escape, class, dot): its source */
  char?: string;
  /** modifier flags in force for a single-character atom (`(?i:…)`, `(?s:…)`) */
  flags?: string;
  /** group alternatives */
  alts?: Term[][];
  /** zero-width (anchor, `\b`, lookaround) */
  zeroWidth?: boolean;
  /** `^` / `$` outside multiline mode */
  anchor?: 'start' | 'end';
  /** a lookaround's direction */
  look?: 'ahead' | 'behind';
  /** a backreference: it reads what its group read (`Backref`) */
  ref?: Backref;
  min: number;
  max: number;
}

/**
 * A backreference (`\1`, `\k<name>`). It reads up to the whole line, so it
 * is analysed as a copy of its group — a superset of what it can read:
 * `(.*)\1x` is `(.*)(?:.*)x`. The copy is optional unless the group has
 * certainly matched by then (a group that is optional, in another
 * alternative, later in the pattern or inside a lookaround leaves the
 * backreference reading nothing).
 */
interface Backref {
  group: number;
  optional: boolean;
  /** modifier flags in force at the backreference (`(?i:\1)` matches case variants) */
  flags: string;
}

/** Where a group or backreference sits: its enclosing groups, with the alternative taken in each. */
type Path = Array<{ term: Term; alt: number }>;

/** Capturing groups of a pattern: how many, and their names. */
function captureGroups(s: string): { count: number; names: Map<string, number> } {
  const names = new Map<string, number>();
  let count = 0;
  for (let i = 0; i < s.length; i++) {
    if (s[i] === '\\') i++;
    else if (s[i] === '[') {
      // JavaScript classes: the first unescaped `]` ends one (`[]`, `[^]`)
      for (i++; i < s.length && s[i] !== ']'; i++) if (s[i] === '\\') i++;
    } else if (s[i] === '(') {
      const named = /^\(\?<([A-Za-z_$][\w$]*)>/.exec(s.slice(i));
      if (named) names.set(named[1], ++count);
      else if (s[i + 1] !== '?') count++;
    }
  }
  return { count, names };
}

class Parser {
  i = 0;
  /** modifier flags in force (`(?i:…)` and friends) */
  flags = '';
  private captures: { count: number; names: Map<string, number> };
  /** the groups enclosing the parse position */
  private path: Path = [];
  /** capturing groups by number: term, enclosing path, where it ends */
  groups: Array<{ term: Term; path: Path; end: number } | undefined> = [];
  private groupCount = 0;
  private refs: Array<{ term: Term; group: number; path: Path; at: number; flags: string }> = [];

  constructor(private src: string) {
    this.captures = captureGroups(src);
  }

  fail(): never {
    throw new Error('unparseable');
  }

  /** The whole pattern, its backreferences resolved. */
  pattern(): Term[][] {
    const root: Term = { min: 1, max: 1 };
    // snapshots of `path` keep the alternative taken at the time
    this.path = [{ term: root, alt: 0 }];
    const alts = this.alternatives();
    if (this.i !== this.src.length) this.fail();
    for (const r of this.refs) this.resolve(r);
    return alts;
  }

  alternatives(): Term[][] {
    const alts: Term[][] = [this.sequence()];
    while (this.src[this.i] === '|') {
      this.i++;
      this.path[this.path.length - 1].alt++;
      alts.push(this.sequence());
    }
    return alts;
  }

  sequence(): Term[] {
    const terms: Term[] = [];
    while (this.i < this.src.length && this.src[this.i] !== '|' && this.src[this.i] !== ')') {
      const term = this.atom();
      this.quantifier(term);
      terms.push(term);
    }
    return terms;
  }

  atom(): Term {
    const s = this.src;
    const c = s[this.i];
    if (c === '(') {
      const term: Term = { min: 1, max: 1 };
      this.i++;
      const outer = this.flags;
      let capturing = s[this.i] !== '?';
      if (s[this.i] === '?') {
        const head = /^\?(?::|=|!|<=|<!|<([A-Za-z_$][\w$]*)>|([ims]*)(?:-([ims]*))?:)/.exec(s.slice(this.i));
        if (!head) this.fail();
        if (/^\?(?:=|!)$/.test(head[0])) term.look = 'ahead';
        if (/^\?(?:<=|<!)$/.test(head[0])) term.look = 'behind';
        capturing = head[1] !== undefined;
        if (head[2] !== undefined) {
          // modifiers (Node 23+): `(?i:…)`, `(?-s:…)`
          const off = head[3] ?? '';
          this.flags = [...new Set([...outer, ...head[2]])].filter(f => !off.includes(f)).join('');
        }
        this.i += head[0].length;
      }
      const group = capturing ? ++this.groupCount : undefined;
      const path = this.path.map(p => ({ ...p }));
      this.path.push({ term, alt: 0 });
      term.alts = this.alternatives();
      this.path.pop();
      this.flags = outer;
      if (s[this.i] !== ')') this.fail();
      this.i++;
      if (group !== undefined) this.groups[group] = { term, path, end: this.i };
      if (term.look) term.zeroWidth = true;
      return term;
    }
    if (c === '[') {
      // JavaScript, not PCRE: `[]` matches nothing and `[^]` any character
      const start = this.i;
      this.i++;
      while (this.i < s.length && s[this.i] !== ']') this.i += s[this.i] === '\\' ? 2 : 1;
      if (this.i >= s.length) this.fail();
      this.i++;
      return { char: s.slice(start, this.i), flags: this.flags, min: 1, max: 1 };
    }
    if (c === '\\') return this.escape();
    if (c === '^' || c === '$') {
      this.i++;
      // multiline (`(?m:…)`): a line boundary, anywhere — zero-width only
      if (this.flags.includes('m')) return { zeroWidth: true, min: 1, max: 1 };
      return { zeroWidth: true, anchor: c === '^' ? 'start' : 'end', min: 1, max: 1 };
    }
    if (c === '*' || c === '+' || c === '?' || c === '{' && /^\{\d+(?:,\d*)?\}/.test(s.slice(this.i))) this.fail();
    this.i++;
    return { char: c, flags: this.flags, min: 1, max: 1 };
  }

  /**
   * An escape outside a class, read the way V8 reads it without the `u`
   * flag (Annex B): `\1` is a backreference only when the pattern has that
   * many groups, else an octal escape (`\10` with one group is `\x08`) or a
   * literal digit (`\8`); `\k` is a backreference only in a pattern with
   * named groups, else the letter `k`; `\c` not followed by a letter is a
   * backslash (and the `c` after it is a literal of its own).
   */
  private escape(): Term {
    const s = this.src;
    const rest = s.slice(this.i);
    const atom = (source: string, length: number): Term => {
      this.i += length;
      return { char: source, flags: this.flags, min: 1, max: 1 };
    };
    if (/^\\[bB]/.test(rest)) {
      this.i += 2;
      return { zeroWidth: true, min: 1, max: 1 };
    }
    const decimal = /^\\(\d+)/.exec(rest);
    if (decimal) {
      const digits = decimal[1];
      if (digits[0] !== '0' && Number(digits) <= this.captures.count) return this.backref(Number(digits), decimal[0].length);
      const octal = /^(?:[0-3][0-7]{0,2}|[4-7][0-7]?)/.exec(digits);
      if (!octal) return atom(digits[0], 2); // `\8`, `\9`
      return atom(`\\x${parseInt(octal[0], 8).toString(16).padStart(2, '0')}`, 1 + octal[0].length);
    }
    if (rest[1] === 'k' && this.captures.names.size > 0) {
      const named = /^\\k<([A-Za-z_$][\w$]*)>/.exec(rest);
      const group = named ? this.captures.names.get(named[1]) : undefined;
      if (!named || group === undefined) this.fail();
      return this.backref(group, named[0].length);
    }
    if (rest[1] === 'c' && !/^\\c[A-Za-z]/.test(rest)) return atom('\\\\', 1);
    // rules compile without the `u` flag: `\u{…}` and `\p{…}` are no escapes there
    const ch = /^\\(?:u[0-9A-Fa-f]{4}|x[0-9A-Fa-f]{2}|c[A-Za-z]|[\s\S])/.exec(rest);
    if (!ch) this.fail();
    return atom(ch[0], ch[0].length);
  }

  private backref(group: number, length: number): Term {
    const term: Term = { min: 1, max: 1 };
    this.refs.push({ term, group, path: this.path.map(p => ({ ...p })), at: this.i, flags: this.flags });
    this.i += length;
    return term;
  }

  /**
   * What a backreference reads: nothing inside its own group (the group
   * hasn't matched yet), else a copy of the group — optional unless the
   * group has certainly matched by then.
   */
  private resolve(r: { term: Term; group: number; path: Path; at: number; flags: string }): void {
    const g = this.groups[r.group];
    if (!g || r.path.some(p => p.term === g.term)) {
      r.term.alts = [[]];
      return;
    }
    let shared = 0;
    while (shared < g.path.length && shared < r.path.length
      && g.path[shared].term === r.path[shared].term && g.path[shared].alt === r.path[shared].alt) shared++;
    // the groups around the group that aren't around the backreference
    const own = g.path.slice(shared).map(p => p.term);
    const certain = g.end <= r.at
      // different alternatives of one group (`(?:(a)|\1)`): never both
      && !(shared < g.path.length && shared < r.path.length && g.path[shared].term === r.path[shared].term)
      && [...own, g.term].every(t => t.min >= 1 && !t.look)
      && own.every(t => t.alts?.length === 1)
      // matched right to left: a group left of it hasn't matched yet
      && !r.path.some(p => p.term.look === 'behind');
    r.term.ref = { group: r.group, optional: !certain, flags: r.flags };
  }
  quantifier(term: Term): void {
    const s = this.src;
    const q = /^(?:\*|\+|\?|\{(\d+)(,(\d*))?\})/.exec(s.slice(this.i));
    if (!q) return;
    this.i += q[0].length;
    if (s[this.i] === '?') this.i++; // lazy: same backtracking on failure
    if (q[0] === '*') [term.min, term.max] = [0, Infinity];
    else if (q[0] === '+') [term.min, term.max] = [1, Infinity];
    else if (q[0] === '?') [term.min, term.max] = [0, 1];
    else {
      term.min = Number(q[1]);
      term.max = q[2] === undefined ? term.min : q[3] === '' ? Infinity : Number(q[3]);
    }
    if (/^(?:\*|\+|\?|\{\d)/.test(s.slice(this.i))) this.fail(); // `a**` is a syntax error anyway
  }
}

/**
 * The characters a pattern is explored with: one UTF-16 code unit (rule
 * regexes have no `u` flag, so `😀` is two) from every interval on which
 * no atom of the pattern changes its mind. Each atom's membership changes
 * only at a range endpoint or a character it names, or at a boundary of a
 * built-in class (`\s`, `.`), so every such point and its neighbours are
 * sampled, plus all of Latin-1. A class that still matches none of them is
 * searched exhaustively (`classSets`), so no non-empty class reads as empty.
 */
function alphabet(source: string): Set<number> {
  const points: number[] = [];
  for (let c = 0; c < 256; c++) points.push(c);
  // \s and line terminators beyond Latin-1, surrogates, the last code unit
  points.push(0x1680, 0x2000, 0x200a, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000, 0xfeff, 0xd800, 0xdbff, 0xdc00, 0xdfff, 0xffff);
  for (let i = 0; i < source.length; i++) points.push(source.charCodeAt(i));
  for (const m of source.matchAll(/\\u([0-9A-Fa-f]{4})|\\x([0-9A-Fa-f]{2})|\\c([A-Za-z])/g)) {
    points.push(m[3] ? m[3].charCodeAt(0) % 32 : parseInt(m[1] ?? m[2], 16));
  }
  // case-insensitive modifiers fold some letters across blocks
  if (/\(\?[a-z]*i/.test(source)) {
    for (const c of [...points]) {
      const ch = String.fromCharCode(c);
      for (const f of [ch.toLowerCase(), ch.toUpperCase()]) if (f.length === 1) points.push(f.charCodeAt(0));
    }
    points.push(0x017f, 0x212a, 0x0130, 0x0131);
  }
  const out = new Set<number>();
  for (const c of points) for (const d of [c - 1, c, c + 1]) if (d >= 0 && d <= 0xffff) out.add(d);
  return out;
}

/** A single-character atom as a whole-string test (with `i`/`s` modifiers), or undefined if it won't compile. */
function atomTest(atom: string, flags: string): RegExp | undefined {
  const mode = (flags.includes('i') ? 'i' : '') + (flags.includes('s') ? 's' : '');
  try {
    return new RegExp(`^(?:${atom})$`, mode);
  } catch {
    return undefined;
  }
}

/**
 * The code units of `chars` each label matches. A label that matches none
 * of them is searched over every code unit: what it matches joins the
 * alphabet (for every label) instead of the label reading as empty.
 */
function classSets(labels: string[], flags: string[], chars: Set<number>): Array<Set<number>> {
  const tests = labels.map((atom, i) => atomTest(atom, flags[i]));
  const compute = () => tests.map(re => {
    const set = new Set<number>();
    for (const c of chars) if (!re || re.test(String.fromCharCode(c))) set.add(c); // won't compile: matches anything
    return set;
  });
  let sets = compute();
  let grown = false;
  sets.forEach((set, i) => {
    const re = tests[i];
    if (set.size > 0 || !re) return;
    for (let c = 0; c <= 0xffff; c++) {
      if (re.test(String.fromCharCode(c))) {
        for (const d of [c - 1, c, c + 1]) if (d >= 0 && d <= 0xffff) chars.add(d);
        grown = true;
        break;
      }
    }
  });
  if (grown) sets = compute();
  return sets;
}

class TooLarge extends Error {}
class EmptyLoop extends Error {}

/** NFA states (after unrolling bounded repeats) above which a pattern isn't analysed. */
const MAX_STATES = 50_000;

/**
 * A bounded repeat whose range is wider than this is analysed as the
 * unbounded loop it behaves like (`.{0,200}` is `.*` for backtracking);
 * narrower ones are unrolled and counted exactly.
 */
const MAX_UNROLLED_RANGE = 4;

/** Polynomial ambiguity: a chain of this many loops (start positions included) is rejected. */
const MAX_LOOP_CHAIN = 2;

/** Most ways bounded repeats and optional groups may split the same text into one state. */
const MAX_SPLITS = 16;

/** Steps (product states, path-count vectors) explored before giving up on a pattern. */
const MAX_WORK = 4_000_000;

/**
 * The pattern as a Thompson NFA: character edges labelled with a
 * single-character atom, epsilon edges (label -1) for alternation,
 * quantifiers and zero-width atoms; `$` has no edge at all (nothing is read
 * after it). Bounded repeats are unrolled the way a backtracking engine
 * counts them: `a{0,3}` is `(?:a(?:a(?:a)?)?)?` (one path per length),
 * `(a?){3}` is three `a?`.
 */
class Nfa {
  /** edges[state] = [label, target] pairs; label -1 = epsilon, -2 = assertion */
  edges: Array<Array<[number, number]>> = [];
  labels: string[] = [];
  labelFlags: string[] = [];
  private labelIds = new Map<string, number>();
  /** lookbehinds: the body, and the state standing for "the lookbehind runs here" */
  lookbehinds: Array<{ alts: Term[][]; at: number }> = [];
  /** groups whose copy (for a backreference) is being built */
  private copying = new Set<number>();
  /** modifier flags a backreference adds to the copy of its group */
  private extraFlags = '';

  /** `groups[n]`: capturing group n, for backreferences */
  constructor(private groups: Array<Term | undefined> = []) {}

  state(): number {
    if (this.edges.length >= MAX_STATES) throw new TooLarge();
    this.edges.push([]);
    return this.edges.length - 1;
  }

  edge(from: number, to: number, label: number): void {
    this.edges[from].push([label, to]);
  }

  label(atom: string, flags = ''): number {
    flags = [...new Set(flags + this.extraFlags)].sort().join('');
    const key = `${flags}\0${atom}`;
    let i = this.labelIds.get(key);
    if (i === undefined) {
      i = this.labels.push(atom) - 1;
      this.labelFlags.push(flags);
      this.labelIds.set(key, i);
    }
    return i;
  }

  sequence(terms: Term[], from: number): number {
    for (const t of terms) from = this.term(t, from);
    return from;
  }

  term(t: Term, from: number): number {
    for (let i = 0; i < t.min; i++) from = this.once(t, from);
    const exit = this.state();
    if (t.max === Infinity || t.max - t.min > MAX_UNROLLED_RANGE) {
      const loop = this.state();
      this.edge(from, loop, -1);
      this.edge(this.once(t, loop), loop, -1);
      this.edge(loop, exit, -1);
    } else {
      for (let i = t.min; i < t.max; i++) {
        this.edge(from, exit, -1);
        from = this.once(t, from);
      }
      this.edge(from, exit, -1);
    }
    return exit;
  }

  /** One unquantified copy of a term. */
  once(t: Term, from: number): number {
    const to = this.state();
    if (t.zeroWidth) {
      if (t.look === 'ahead' && t.alts) {
        // the body runs from here: a branch that reads on and ends nowhere
        // (it backtracks like any other part, `.+(?=.*=)` is `.+.*=`)
        const body = this.state();
        this.edge(from, body, -2);
        this.once({ alts: t.alts, min: 1, max: 1 }, body);
      } else if (t.look === 'behind' && t.alts) {
        // the body runs leftwards from here, analysed on its own
        // (`backtrackingReason`); this state, reading anything forever, only
        // tells how often the pattern gets here
        const at = this.state();
        this.edge(from, at, -2);
        this.edge(at, at, this.label('[\\s\\S]'));
        this.lookbehinds.push({ alts: t.alts, at });
      }
      // an assertion (label -2): read nothing, like epsilon, but it can fail —
      // a state behind one hasn't matched yet. `$` has no edge at all.
      if (t.anchor !== 'end') this.edge(from, to, -2);
    } else if (t.ref) {
      const group = this.groups[t.ref.group];
      const copy = group?.alts !== undefined && !this.copying.has(t.ref.group);
      if (group?.alts && copy) {
        const flags = this.extraFlags;
        this.copying.add(t.ref.group);
        this.extraFlags += t.ref.flags;
        this.edge(this.once({ alts: group.alts, min: 1, max: 1 }, from), to, -1);
        this.extraFlags = flags;
        this.copying.delete(t.ref.group);
      }
      // reads nothing when its group hasn't matched (or inside its own copy)
      if (t.ref.optional || !copy) this.edge(from, to, -1);
    } else if (t.char !== undefined) {
      this.edge(from, to, this.label(t.char, t.flags));
    } else {
      for (const alt of t.alts ?? []) {
        const start = this.state();
        this.edge(from, start, -1);
        this.edge(this.sequence(alt, start), to, -1);
      }
    }
    return to;
  }
}

/**
 * Epsilon paths from each state to the states it reaches without reading a
 * character, with how many distinct paths lead there. A cycle of epsilon
 * edges is a repeated group that can match empty text: `(a*)*`, `(a|b?)+`.
 */
function epsilonClosures(nfa: Nfa): Array<Map<number, number>> {
  const closures: Array<Map<number, number> | undefined> = [];
  const onStack = new Set<number>();
  let size = 0;
  const visit = (p: number): Map<number, number> => {
    const done = closures[p];
    if (done) return done;
    if (onStack.has(p)) throw new EmptyLoop();
    onStack.add(p);
    const out = new Map<number, number>([[p, 1]]);
    for (const [label, q] of nfa.edges[p]) {
      if (label >= 0) continue;
      for (const [r, k] of visit(q)) out.set(r, Math.min(1e12, (out.get(r) ?? 0) + k));
    }
    onStack.delete(p);
    size += out.size;
    if (size > MAX_WORK) throw new TooLarge();
    closures[p] = out;
    return out;
  };
  // deep epsilon chains (long unrolled repeats) without deep recursion
  for (let p = nfa.edges.length - 1; p >= 0; p--) visit(p);
  return closures as Array<Map<number, number>>;
}

/** A character edge of the epsilon-free graph. */
interface Edge {
  /** character classes the edge reads (bit per class) */
  mask: bigint;
  to: number;
  /** distinct NFA paths it stands for (`(a|a)` is two) */
  mult: number;
}

interface Graph {
  edges: Edge[][];
  start: number;
}

class TooComplex extends Error {}

/** Strongly connected components; `loop[c]` when component c has a cycle. */
function components(g: Graph): { comp: number[]; members: number[][]; loop: boolean[] } {
  const n = g.edges.length;
  const index = new Array<number>(n).fill(-1);
  const low = new Array<number>(n).fill(0);
  const onStack = new Array<boolean>(n).fill(false);
  const comp = new Array<number>(n).fill(-1);
  const members: number[][] = [];
  const stack: number[] = [];
  let next = 0;
  for (let root = 0; root < n; root++) {
    if (index[root] !== -1) continue;
    const work: Array<[number, number]> = [[root, 0]];
    while (work.length > 0) {
      const frame = work[work.length - 1];
      const v = frame[0];
      if (frame[1] === 0) {
        index[v] = low[v] = next++;
        stack.push(v);
        onStack[v] = true;
      }
      const out = g.edges[v];
      if (frame[1] < out.length) {
        const w = out[frame[1]++].to;
        if (index[w] === -1) work.push([w, 0]);
        else if (onStack[w]) low[v] = Math.min(low[v], index[w]);
        continue;
      }
      work.pop();
      if (work.length > 0) {
        const parent = work[work.length - 1][0];
        low[parent] = Math.min(low[parent], low[v]);
      }
      if (low[v] === index[v]) {
        const c = members.length;
        const list: number[] = [];
        let w: number;
        do {
          w = stack.pop() as number;
          onStack[w] = false;
          comp[w] = c;
          list.push(w);
        } while (w !== v);
        members.push(list);
      }
    }
  }
  const loop = members.map((list, c) => list.length > 1 || g.edges[list[0]].some(e => e.to === list[0] && comp[e.to] === c));
  return { comp, members, loop };
}

/**
 * Exponential ambiguity inside a loop component: a state with two
 * different cycles reading the same text. In the product of the component
 * with itself, a cycle through a diagonal state (p,p) that takes two
 * different edges somewhere.
 */
function exponential(g: Graph, members: number[], comp: number[], c: number, budget: { work: number }): boolean {
  const k = members.length;
  const local = new Map(members.map((s, i) => [s, i]));
  const inner = members.map(s => g.edges[s].filter(e => comp[e.to] === c));
  const pg: Graph = { edges: [], start: 0 };
  const diverging: Array<[number, number]> = [];
  for (let i = 0; i < k; i++) {
    for (let j = 0; j < k; j++) {
      const out: Edge[] = [];
      for (const e1 of inner[i]) {
        for (const e2 of inner[j]) {
          if (++budget.work > MAX_WORK) throw new TooComplex();
          const mask = e1.mask & e2.mask;
          if (mask === 0n) continue;
          const to = (local.get(e1.to) as number) * k + (local.get(e2.to) as number);
          out.push({ mask, to, mult: 1 });
          if (e1 !== e2 || e1.mult > 1) diverging.push([i * k + j, to]);
        }
      }
      pg.edges.push(out);
    }
  }
  const prod = components(pg);
  const hasDiagonal = new Set<number>();
  for (let i = 0; i < k; i++) hasDiagonal.add(prod.comp[i * k + i]);
  return diverging.some(([a, b]) => prod.comp[a] === prod.comp[b] && hasDiagonal.has(prod.comp[a]));
}

/**
 * Whether loop component B can follow loop component A reading the same
 * text: some p in A, q in B and text v with p -v-> p, p -v-> q, q -v-> q
 * (polynomial ambiguity). A search of the triple product from (p,p,q) to
 * (p,q,q), the first and last walkers kept inside their loop.
 */
function chained(g: Graph, comp: number[], a: number[], ca: number, b: number[], cb: number, budget: { work: number }): boolean {
  const n = g.edges.length;
  const kb = b.length;
  const la = new Map(a.map((s, i) => [s, i]));
  const lb = new Map(b.map((s, i) => [s, i]));
  for (const p of a) {
    for (const q of b) {
      const key = (x: number, y: number, z: number) => ((la.get(x) as number) * n + y) * kb + (lb.get(z) as number);
      const target = key(p, q, q);
      const seen = new Set<number>([key(p, p, q)]);
      const queue: Array<[number, number, number]> = [[p, p, q]];
      while (queue.length > 0) {
        const [x, y, z] = queue.pop() as [number, number, number];
        for (const e1 of g.edges[x]) {
          if (comp[e1.to] !== ca) continue;
          for (const e2 of g.edges[y]) {
            const m12 = e1.mask & e2.mask;
            if (m12 === 0n) continue;
            for (const e3 of g.edges[z]) {
              if (++budget.work > MAX_WORK) throw new TooComplex();
              if (comp[e3.to] !== cb || (m12 & e3.mask) === 0n) continue;
              const id = key(e1.to, e2.to, e3.to);
              if (id === target) return true;
              if (seen.has(id)) continue;
              seen.add(id);
              queue.push([e1.to, e2.to, e3.to]);
            }
          }
        }
      }
    }
  }
  return false;
}

/** What the loops of a graph cost. */
interface Loops {
  /** why they backtrack too much (exponential, or a chain of loops too long) */
  reason?: string;
  /** the longest chain of loops that can read the same text (0: no loop) */
  degree: number;
  /** the longest such chain ending at a node's loop, that loop included */
  chainInto(node: number): number;
}

/**
 * The loops of a graph. Nodes in `markers` (where a lookbehind runs) aren't
 * loops of the pattern: they count only for `chainInto`.
 */
function loopAnalysis(g: Graph, budget: { work: number }, markers = new Set<number>()): Loops {
  const { comp, members, loop } = components(g);
  const marker = new Set([...markers].map(n => comp[n]));
  const loops = members.map((_, c) => c).filter(c => loop[c] && !marker.has(c));
  // Tarjan numbers components in reverse topological order: successors first
  const reach = members.map(() => new Set<number>());
  for (let c = 0; c < members.length; c++) {
    for (const s of members[c]) {
      for (const e of g.edges[s]) {
        const d = comp[e.to];
        if (d === c) continue;
        reach[c].add(d);
        for (const r of reach[d]) reach[c].add(r);
      }
    }
  }
  const into = new Map<number, number>();
  const chainIntoComponent = (c: number): number => {
    let best = into.get(c);
    if (best !== undefined) return best;
    best = 1;
    // predecessors have higher numbers: the recursion ends
    for (const d of loops) {
      if (d === c || !reach[d].has(c)) continue;
      if (chained(g, comp, members[d], d, members[c], c, budget)) best = Math.max(best, chainIntoComponent(d) + 1);
    }
    into.set(c, best);
    return best;
  };
  const result: Loops = { degree: 0, chainInto: node => chainIntoComponent(comp[node]) };

  for (const c of loops) {
    if (exponential(g, members[c], comp, c, budget)) {
      result.reason = 'a repeated part can match the same text in exponentially many ways (nested or overlapping quantifiers)';
      return result;
    }
  }
  const chain = new Map<number, number>();
  for (const c of loops) {
    let best = 1;
    for (const d of loops) {
      if (d === c || !reach[c].has(d) || (chain.get(d) ?? 1) + 1 <= best) continue;
      if (chained(g, comp, members[c], c, members[d], d, budget)) best = (chain.get(d) as number) + 1;
    }
    chain.set(c, best);
    result.degree = Math.max(result.degree, best);
    if (best > MAX_LOOP_CHAIN) {
      result.reason = 'unbounded quantifiers in a row can match the same text (polynomial backtracking: three or more, counting the search over start positions)';
      return result;
    }
  }
  return result;
}

/**
 * Finite ambiguity: how many paths can reach one state reading the same
 * text, explored over every text (one representative character per class
 * the atoms can't tell apart). Growth that only comes from going round a
 * loop is the loop analysis's business, so inside a loop component counts
 * take the maximum instead of adding up.
 */
function splitsReason(g: Graph, classes: number, budget: { work: number }): string | undefined {
  const { comp, loop } = components(g);
  const seen = new Set<string>();
  const queue: Array<Map<number, number>> = [new Map([[g.start, 1]])];
  while (queue.length > 0) {
    const vector = queue.pop() as Map<number, number>;
    for (let cls = 0; cls < classes; cls++) {
      const bit = 1n << BigInt(cls);
      const cross = new Map<number, number>();
      const inner = new Map<number, number>();
      for (const [p, count] of vector) {
        for (const e of g.edges[p]) {
          if (++budget.work > MAX_WORK) throw new TooComplex();
          if ((e.mask & bit) === 0n) continue;
          const add = Math.min(1e12, count * e.mult);
          if (comp[p] === comp[e.to] && loop[comp[p]]) inner.set(e.to, Math.max(inner.get(e.to) ?? 0, add));
          else cross.set(e.to, Math.min(1e12, (cross.get(e.to) ?? 0) + add));
        }
      }
      const next = new Map<number, number>();
      for (const [q, k] of cross) next.set(q, k);
      for (const [q, k] of inner) next.set(q, Math.max(next.get(q) ?? 0, k));
      if (next.size === 0) continue;
      for (const k of next.values()) {
        if (k > MAX_SPLITS) return 'the same text can be split many different ways (bounded repeats or optional groups that overlap)';
      }
      const key = [...next].sort((x, y) => x[0] - y[0]).map(([q, k]) => `${q}:${k}`).join(',');
      if (seen.has(key)) continue;
      seen.add(key);
      queue.push(next);
    }
  }
  return undefined;
}

/** Whether every top-level alternative starts with `^`: the search tries position 0 only. */
function anchoredAtStart(alts: Term[][]): boolean {
  return alts.every(seq => {
    for (const t of seq) {
      if (t.anchor === 'start') return true;
      if (t.zeroWidth) continue; // \b, lookaround: still at the start
      return t.alts !== undefined && t.min >= 1 && anchoredAtStart(t.alts);
    }
    return false;
  });
}

/**
 * A lookbehind body the way it is matched: right to left. `$` inside it is
 * an assertion like any other (nothing after it is unreachable any more).
 */
function reversed(alts: Term[][]): Term[][] {
  return alts.map(seq => [...seq].reverse().map(t => {
    if (t.anchor) return { ...t, anchor: undefined };
    return t.alts && !t.look ? { ...t, alts: reversed(t.alts) } : t;
  }));
}

/**
 * Why one pattern (top level or a lookbehind body) is unsafe, and how
 * many loops in a row its own matching costs (`degree`: n^degree steps).
 */
function backtrackingReason(
  alts: Term[][], anchored: boolean, chars: Set<number>, groups: Array<Term | undefined>,
): { reason?: string; degree: number } {
  const nfa = new Nfa(groups);
  let start: number;
  let final: number;
  let closures: Array<Map<number, number>>;
  try {
    start = nfa.state();
    final = nfa.once({ alts, min: 1, max: 1 }, start);
    closures = epsilonClosures(nfa);
  } catch (err) {
    if (err instanceof TooLarge) return { reason: 'the pattern is too large to be analysed for backtracking', degree: 0 };
    if (err instanceof EmptyLoop) return { reason: 'a repeated group can match empty text', degree: 0 };
    throw err;
  }

  // one class per set of sample characters the labels can't tell apart
  const sets = classSets(nfa.labels, nfa.labelFlags, chars);
  const classOf = new Map<string, number>();
  const masks = sets.map(() => 0n);
  for (const c of chars) {
    const signature = sets.map(set => (set.has(c) ? '1' : '0')).join('');
    if (!signature.includes('1')) continue;
    let cls = classOf.get(signature);
    if (cls === undefined) {
      cls = classOf.size;
      classOf.set(signature, cls);
      sets.forEach((set, i) => { if (set.has(c)) masks[i] |= 1n << BigInt(cls as number); });
    }
  }
  const classes = classOf.size;

  // A state from which the pattern has matched: final reached through plain
  // epsilon edges, no assertion that could still fail (`.*(?=x)` hasn't)
  const done = new Map<number, boolean>();
  const matched = (p: number): boolean => {
    let r = done.get(p);
    if (r === undefined) {
      done.set(p, false);
      r = p === final || nfa.edges[p].some(([label, q]) => label === -1 && matched(q));
      done.set(p, r);
    }
    return r;
  };

  // the epsilon-free graph: the start state and every state a character leads to
  const ids = new Map<number, number>([[start, 0]]);
  for (const out of nfa.edges) for (const [label, q] of out) if (label >= 0 && !ids.has(q)) ids.set(q, ids.size);
  const edges: Edge[][] = [];
  const accepting: boolean[] = [];
  for (const [state] of ids) {
    const merged = new Map<string, Edge>();
    for (const [r, k] of closures[state]) {
      for (const [label, q] of nfa.edges[r]) {
        if (label < 0) continue;
        const key = `${label}:${q}`;
        const e = merged.get(key);
        if (e) e.mult = Math.min(1e12, e.mult + k);
        else merged.set(key, { mask: masks[label], to: ids.get(q) as number, mult: k });
      }
    }
    edges.push([...merged.values()].filter(e => e.mask !== 0n));
    accepting.push(matched(state));
  }
  // where lookbehinds run: not part of what the pattern reads
  const markers = new Set(nfa.lookbehinds.map(lb => ids.get(lb.at) as number));
  const unmarked = edges.map((out, i) => (markers.has(i) ? [] : out.filter(e => !markers.has(e.to))));

  const budget = { work: 0 };
  let degree: number;
  let search: Loops;
  try {
    // Anything the pattern can do once it has started matching
    const whole: Graph = { edges: unmarked, start: 0 };
    const loops = loopAnalysis(whole, budget);
    const reason = loops.reason ?? splitsReason(whole, classes, budget);
    if (reason) return { reason, degree: 0 };
    degree = loops.degree;
    // The search: start positions as one more loop in front, and states
    // where the pattern has matched as dead ends (the search stops there)
    const all = (1n << BigInt(classes)) - 1n;
    const searchEdges = edges.map((out, i) => (accepting[i] ? [] : out));
    if (!anchored && !accepting[0]) {
      const s = searchEdges.length;
      searchEdges.push([{ mask: all, to: s, mult: 1 }, ...searchEdges[0]]);
    }
    search = loopAnalysis({ edges: searchEdges, start: 0 }, budget, markers);
    // fine once started: only where matching starts is the problem
    if (search.reason) return { reason: `${search.reason} — drop a leading \`.*\` or anchor the pattern with \`^\``, degree: 0 };
  } catch (err) {
    if (err instanceof TooComplex) return { reason: 'the pattern is too complex to be analysed for backtracking', degree: 0 };
    throw err;
  }

  // A lookbehind costs its body's matching (right to left, from where it
  // runs) each time the pattern gets there: n^(chain of loops leading
  // there) times. `\w+(?<=\w*!)` is three loops: start positions, `\w+`, `\w*`.
  for (const lb of nfa.lookbehinds) {
    // only optional single characters (`(?<=\w*\s*)`): the first way it tries
    // succeeds, so it reads the line once and never backtracks
    const linear = lb.alts.length === 1 && lb.alts[0].every(t => t.min === 0 && t.char !== undefined);
    const body = linear
      ? { degree: lb.alts[0].some(t => t.max === Infinity || t.max > MAX_UNROLLED_RANGE) ? 1 : 0 }
      : backtrackingReason(reversed(lb.alts), true, chars, groups);
    if (body.reason) return body;
    if (body.degree === 0) continue;
    let visits: number;
    try {
      visits = search.chainInto(ids.get(lb.at) as number) - 1;
    } catch (err) {
      if (err instanceof TooComplex) return { reason: 'the pattern is too complex to be analysed for backtracking', degree: 0 };
      throw err;
    }
    if (visits + body.degree > MAX_LOOP_CHAIN) {
      return {
        reason: 'a lookbehind with an unbounded quantifier runs behind unbounded quantifiers that can read the same text (polynomial backtracking: three or more loops, counting the search over start positions)',
        degree: 0,
      };
    }
    degree = Math.max(degree, visits + body.degree);
  }
  return { degree };
}

/**
 * Why a rule regex is unsafe to run (super-linear backtracking), or
 * undefined when it is safe. The source must already compile.
 */
export function unsafeRegexReason(source: string): string | undefined {
  let alts: Term[][];
  let groups: Array<Term | undefined>;
  try {
    const p = new Parser(source);
    alts = p.pattern();
    groups = p.groups.map(g => g?.term);
  } catch {
    return 'the pattern could not be analysed for backtracking';
  }
  return backtrackingReason(alts, anchoredAtStart(alts), alphabet(source), groups).reason;
}

/** Text a rule regex runs on, capped at MAX_RULE_INPUT characters. */
export function ruleInput(text: string): string {
  return text.length > MAX_RULE_INPUT ? text.slice(0, MAX_RULE_INPUT) : text;
}
