/**
 * Static screen for declarative-rule regexes that can backtrack
 * super-linearly. Rules come from files a scan picks up (a repository's
 * `.vaso/rules/` included), and a rule like `(a+)+$` used to hang a scan on a
 * 41-character config line. JavaScript's engine backtracks, so the shapes
 * that blow up are rejected before a rule is compiled:
 *
 *   - a quantified group that repeats a variable-length quantifier inside it
 *     (`(a+)+`, `(\w+\s?)*`, `(.*a){12}`) — exponential;
 *   - a repeated group whose alternatives can start with the same character
 *     (`(a|ab)*`, `(\w|\d)+`) — exponential;
 *   - unbounded quantifiers on overlapping atoms in a row, with only
 *     optional atoms between them (`\d+\d+`, `.*.*`, `\w*\s?\w+`) —
 *     polynomial.
 *
 * Rule input is also length-capped (MAX_RULE_INPUT), so what remains is
 * linear or close to it. Patterns the parser can't follow are rejected.
 */

/** Longest text (one line, one config value) a rule regex is run on. */
export const MAX_RULE_INPUT = 4096;

interface Term {
  /** single-character atom (literal, escape, class, dot): its source */
  char?: string;
  /** group alternatives */
  alts?: Term[][];
  /** zero-width (anchor, lookaround, backreference) */
  zeroWidth?: boolean;
  min: number;
  max: number;
}

class Parser {
  i = 0;
  constructor(private src: string) {}

  fail(): never {
    throw new Error('unparseable');
  }

  alternatives(): Term[][] {
    const alts: Term[][] = [this.sequence()];
    while (this.src[this.i] === '|') {
      this.i++;
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
      this.i++;
      let lookaround = false;
      if (s[this.i] === '?') {
        const head = /^\?(?::|=|!|<=|<!|<[A-Za-z_$][\w$]*>)/.exec(s.slice(this.i));
        if (!head) this.fail();
        lookaround = /^\?(?:=|!|<=|<!)$/.test(head[0]);
        this.i += head[0].length;
      }
      const alts = this.alternatives();
      if (s[this.i] !== ')') this.fail();
      this.i++;
      return lookaround ? { alts, zeroWidth: true, min: 1, max: 1 } : { alts, min: 1, max: 1 };
    }
    if (c === '[') {
      const start = this.i;
      this.i++;
      if (s[this.i] === '^') this.i++;
      if (s[this.i] === ']') this.i++;
      while (this.i < s.length && s[this.i] !== ']') this.i += s[this.i] === '\\' ? 2 : 1;
      if (this.i >= s.length) this.fail();
      this.i++;
      return { char: s.slice(start, this.i), min: 1, max: 1 };
    }
    if (c === '\\') {
      const esc = /^\\(?:[bB]|\d+|k<[^>]+>)/.exec(s.slice(this.i));
      if (esc) {
        this.i += esc[0].length;
        return { zeroWidth: true, min: 1, max: 1 };
      }
      const ch = /^\\(?:u\{[0-9A-Fa-f]+\}|u[0-9A-Fa-f]{4}|x[0-9A-Fa-f]{2}|c[A-Za-z]|[pP]\{[^}]+\}|[\s\S])/.exec(s.slice(this.i));
      if (!ch) this.fail();
      this.i += ch[0].length;
      return { char: ch[0], min: 1, max: 1 };
    }
    if (c === '^' || c === '$') {
      this.i++;
      return { zeroWidth: true, min: 1, max: 1 };
    }
    if (c === '*' || c === '+' || c === '?' || c === '{' && /^\{\d+(?:,\d*)?\}/.test(s.slice(this.i))) this.fail();
    this.i++;
    return { char: c, min: 1, max: 1 };
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

const SAMPLE = (() => {
  const chars: string[] = [];
  for (let c = 0; c < 256; c++) chars.push(String.fromCharCode(c));
  chars.push('é', '中', ' ', 'а', '\u{1F600}');
  return chars;
})();

const charSets = new Map<string, Set<string>>();

/** The sample characters a single-character atom matches. */
function charSet(atom: string): Set<string> {
  let set = charSets.get(atom);
  if (!set) {
    set = new Set();
    try {
      const re = new RegExp(`^(?:${atom})$`, 'u');
      for (const c of SAMPLE) if (re.test(c)) set.add(c);
    } catch {
      try {
        const re = new RegExp(`^(?:${atom})$`);
        for (const c of SAMPLE) if (re.test(c)) set.add(c);
      } catch {
        for (const c of SAMPLE) set.add(c); // unknown: assume it matches anything
      }
    }
    charSets.set(atom, set);
  }
  return set;
}

function overlaps(a: Set<string>, b: Set<string>): boolean {
  for (const c of a) if (b.has(c)) return true;
  return false;
}

/** Characters a term can start with (undefined: can't tell / matches empty only). */
function firstChars(terms: Term[]): Set<string> | undefined {
  const out = new Set<string>();
  for (const t of terms) {
    if (t.zeroWidth) continue;
    const first = t.char !== undefined
      ? charSet(t.char)
      : t.alts
        ? t.alts.map(firstChars).reduce<Set<string> | undefined>((acc, s) => (acc && s ? new Set([...acc, ...s]) : undefined), new Set())
        : undefined;
    if (!first) return undefined;
    for (const c of first) out.add(c);
    if (t.min > 0 && !canBeEmpty(t)) return out;
  }
  return out;
}

function canBeEmpty(t: Term): boolean {
  if (t.zeroWidth || t.min === 0) return true;
  if (t.alts) return t.alts.some(seq => seq.every(canBeEmpty));
  return false;
}

/**
 * Whether terms contain (anywhere inside) a quantifier that can repeat a
 * variable number of times: unbounded only (`+`, `*`, `{n,}`), or also a
 * bounded range above one (`{1,5}`) — `?` alone doesn't make the split of
 * the input between iterations ambiguous.
 */
function hasVariableRepeat(terms: Term[], unboundedOnly: boolean): boolean {
  return terms.some(t => (t.max > t.min && (t.max === Infinity || (!unboundedOnly && t.max > 1)))
    || (t.alts?.some(seq => hasVariableRepeat(seq, unboundedOnly)) ?? false));
}

function checkSequence(terms: Term[]): string | undefined {
  for (let n = 0; n < terms.length; n++) {
    const t = terms[n];
    if (t.alts) {
      if (t.max > 1 && !t.zeroWidth) {
        // a repeated group that repeats a variable-length part
        const inner = t.max === Infinity
          ? t.alts.some(seq => hasVariableRepeat(seq, false)) || canBeEmpty({ ...t, min: 1 })
          : t.alts.some(seq => hasVariableRepeat(seq, true));
        if (inner) return 'a quantified group repeats a variable-length quantifier inside it (nested quantifiers)';
        if (t.max === Infinity && t.alts.length > 1) {
          const starts = t.alts.map(firstChars);
          for (let a = 0; a < starts.length; a++) {
            for (let b = a + 1; b < starts.length; b++) {
              const sa = starts[a];
              const sb = starts[b];
              if (sa && sb && overlaps(sa, sb)) return 'a repeated group has alternatives that can match the same text';
            }
          }
        }
      }
      for (const seq of t.alts) {
        const r = checkSequence(seq);
        if (r) return r;
      }
    }
    // unbounded atoms in a row (only optional atoms between) that overlap
    if (t.char !== undefined && t.max === Infinity) {
      const set = charSet(t.char);
      for (let m = n + 1; m < terms.length; m++) {
        const u = terms[m];
        if (u.char !== undefined && u.max === Infinity && overlaps(set, charSet(u.char))) {
          return 'adjacent unbounded quantifiers can match the same text';
        }
        if (!canBeEmpty(u)) break;
      }
    }
  }
  return undefined;
}

/**
 * Why a rule regex is unsafe to run (super-linear backtracking), or
 * undefined when it is safe. The source must already compile.
 */
export function unsafeRegexReason(source: string): string | undefined {
  let alts: Term[][];
  try {
    const p = new Parser(source);
    alts = p.alternatives();
    if (p.i !== source.length) return 'the pattern could not be analysed for backtracking';
  } catch {
    return 'the pattern could not be analysed for backtracking';
  }
  const top: Term = { alts, min: 1, max: 1 };
  return checkSequence([top]);
}

/** Text a rule regex runs on, capped at MAX_RULE_INPUT characters. */
export function ruleInput(text: string): string {
  return text.length > MAX_RULE_INPUT ? text.slice(0, MAX_RULE_INPUT) : text;
}
