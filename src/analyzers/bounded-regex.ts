import { createContext, runInContext, type Context } from 'node:vm';
import { performance } from 'node:perf_hooks';
import { unsafeRegexReason } from '../rules/regex-safety.js';

/**
 * Run a regex taken from a scanned config against a few fixed samples
 * (sample commands, sensitive paths). The pattern decides what the agent
 * lets through, so it can't be skipped because it might backtrack: a
 * catch-all like `(.|\s)*`, `(.+)+` or `.*.*.*` must still be judged.
 *
 * A pattern the static screen (`unsafeRegexReason`) finds linear runs
 * directly. Any other pattern runs on the same short samples under a time
 * limit: a catch-all matches on its first greedy path, and only a pattern
 * that fails a sample in exponentially many ways can run long. When the
 * limit is hit the result is incomplete — "not evaluated", which callers
 * report rather than read as "doesn't match".
 *
 * The patterns judged by one check go through `runSampleBatch` in two
 * passes. First every unscreened pattern gets a short slice of its own
 * (`REGEX_FIRST_PASS_MS`): a catch-all matches on its first greedy path in
 * microseconds, so no number of slow patterns listed before it can keep it
 * from being judged. Then the patterns still undecided share the check's
 * `RegexBudget`; once that is spent the rest stay "not evaluated" (`budget`),
 * so a config listing hundreds of hostile patterns costs seconds, not
 * minutes. Screened patterns always run, so their verdicts don't depend on
 * timing.
 *
 * A pattern cut short still keeps what it showed: the samples matched before
 * the limit, and those matched by any top-level alternative the screen finds
 * linear (`.*|(.|.)*Z` matches everything through `.*` alone).
 */

/** Time limit for one pattern over all its samples. */
export const REGEX_SAMPLE_BUDGET_MS = 250;

/** Total time for the unscreened patterns of one check run. */
export const REGEX_TOTAL_BUDGET_MS = 1500;

/** First-pass slice for each unscreened pattern of a batch. */
export const REGEX_FIRST_PASS_MS = 5;

/** First-pass time after which the remaining slices shrink to 1 ms. */
const FIRST_PASS_TOTAL_MS = 1000;

/** Longest sample text; the samples are short commands and paths. */
const MAX_SAMPLE_LENGTH = 512;

/** Time left for one check's unscreened patterns. */
export interface RegexBudget {
  remainingMs: number;
}

export function regexBudget(totalMs = REGEX_TOTAL_BUDGET_MS): RegexBudget {
  return { remainingMs: totalMs };
}

export interface SampleRun {
  /** Per sample: matched. When incomplete, false may also mean "not known". */
  hits: boolean[];
  /** Every sample was decided. */
  complete: boolean;
  /** Why it is incomplete: the pattern ran out of time, or the check's budget was spent before it ran. */
  reason?: 'timeout' | 'budget';
}

let sandbox: Context | undefined;

const strip = (flags: string): string => flags.replace(/[gy]/g, '');

/** Index of the `)` closing the group opened at `open` in a JS regex source, or -1. */
function closingParen(source: string, open: number): number {
  let depth = 0;
  for (let i = open; i < source.length; i++) {
    const c = source[i];
    if (c === '\\') { i++; continue; }
    if (c === '[') {
      for (i++; i < source.length && source[i] !== ']'; i++) if (source[i] === '\\') i++;
      continue;
    }
    if (c === '(') depth++;
    else if (c === ')' && --depth === 0) return i;
  }
  return -1;
}

/** Top-level `|` alternatives of a JS regex source. */
function splitAlternatives(source: string): string[] {
  const out: string[] = [];
  let depth = 0;
  let start = 0;
  for (let i = 0; i < source.length; i++) {
    const c = source[i];
    if (c === '\\') { i++; continue; }
    if (c === '[') {
      for (i++; i < source.length && source[i] !== ']'; i++) if (source[i] === '\\') i++;
      continue;
    }
    if (c === '(') depth++;
    else if (c === ')') depth--;
    else if (c === '|' && depth === 0) {
      out.push(source.slice(start, i));
      start = i + 1;
    }
  }
  out.push(source.slice(start));
  return out;
}

/**
 * The top-level alternatives of `re` as standalone sources, keeping a
 * `^(?:…)$` wrapper; undefined when there is only one or the pattern uses
 * backreferences (an alternative alone would renumber them).
 */
function alternatives(source: string): string[] | undefined {
  if (/\\[1-9]|\\k</.test(source)) return undefined;
  let body = source;
  let anchored = false;
  if (body.startsWith('^(?:') && body.endsWith(')$') && closingParen(body, 1) === body.length - 2) {
    anchored = true;
    body = body.slice(4, -2);
  }
  for (;;) {
    const open = /^\((?:\?:|\?<[A-Za-z_$][\w$]*>)?/.exec(body);
    if (!open || closingParen(body, 0) !== body.length - 1) break;
    body = body.slice(open[0].length, -1);
  }
  const parts = splitAlternatives(body);
  if (parts.length < 2) return undefined;
  return parts.map(p => (anchored ? `^(?:${p})$` : p));
}

/** Samples matched by any alternative of `re` the screen finds linear (never times out). */
function linearAlternativeHits(re: RegExp, texts: readonly string[]): boolean[] {
  const hits = texts.map(() => false);
  for (const alt of alternatives(re.source) ?? []) {
    if (unsafeRegexReason(alt)) continue;
    let r: RegExp;
    try {
      r = new RegExp(alt, strip(re.flags));
    } catch {
      continue;
    }
    texts.forEach((t, i) => { hits[i] ||= r.test(t); });
  }
  return hits;
}

/**
 * Whether `re` matches each sample (`re.test`). With `untilMiss` the samples
 * are tried in order and the first miss ends the run (the rest read as
 * misses): a caller asking "does it match all of these" passes the shortest
 * samples first, so a pattern that fails is told apart before it can
 * backtrack on a long one.
 */
export function runSamples(
  re: RegExp,
  samples: readonly string[],
  opts: { untilMiss?: boolean; budgetMs?: number; budget?: RegexBudget } = {},
): SampleRun {
  return run(re, samples, opts, true);
}

const clip = (samples: readonly string[]): string[] => samples.map(s => (s.length > MAX_SAMPLE_LENGTH ? s.slice(0, MAX_SAMPLE_LENGTH) : s));

/** `runSamples`; without `rescue`, a timed-out run skips the linear-alternative hits (a later pass adds them). */
function run(
  re: RegExp,
  samples: readonly string[],
  opts: { untilMiss?: boolean; budgetMs?: number; budget?: RegexBudget },
  rescue: boolean,
): SampleRun {
  const texts = clip(samples);
  const untilMiss = !!opts.untilMiss;
  if (!unsafeRegexReason(re.source)) {
    const plain = new RegExp(re.source, strip(re.flags));
    let missed = false;
    return { hits: texts.map(t => !(missed && untilMiss) && (plain.test(t) || ((missed = true), false))), complete: true };
  }
  const budget = opts.budget;
  const limit = Math.min(opts.budgetMs ?? REGEX_SAMPLE_BUDGET_MS, budget ? budget.remainingMs : Infinity);
  if (limit <= 0) return { hits: linearAlternativeHits(re, texts), complete: false, reason: 'budget' };

  sandbox ??= createContext(Object.create(null));
  sandbox.source = re.source;
  sandbox.flags = strip(re.flags);
  sandbox.texts = texts;
  sandbox.untilMiss = untilMiss;
  sandbox.out = undefined;
  const started = performance.now();
  try {
    // results are kept as they come, so a timeout keeps the samples already matched
    runInContext(
      '(() => { out = []; const r = new RegExp(source, flags); let missed = false; for (const t of texts) out.push(!(missed && untilMiss) && (r.test(t) || ((missed = true), false))); })()',
      sandbox,
      { timeout: Math.max(1, Math.ceil(limit)) },
    );
    const out = sandbox.out as unknown;
    if (Array.isArray(out) && out.length === texts.length) return { hits: out.map(Boolean), complete: true };
    return { hits: texts.map(() => false), complete: false, reason: 'timeout' };
  } catch {
    const partial = Array.isArray(sandbox.out) ? (sandbox.out as unknown[]).map(Boolean) : [];
    const alt = rescue ? linearAlternativeHits(re, texts) : [];
    return { hits: texts.map((_, i) => !!partial[i] || alt[i]), complete: false, reason: 'timeout' };
  } finally {
    if (budget) budget.remainingMs -= performance.now() - started;
    sandbox.texts = undefined;
    sandbox.out = undefined;
  }
}

/** `runSamples` hits, or undefined when the run is incomplete ("not evaluated"). */
export function testSamples(re: RegExp, samples: readonly string[], opts: { untilMiss?: boolean; budgetMs?: number; budget?: RegexBudget } = {}): boolean[] | undefined {
  const run = runSamples(re, samples, opts);
  return run.complete ? run.hits : undefined;
}

export interface SampleJob {
  re: RegExp;
  samples: readonly string[];
  untilMiss?: boolean;
}

/**
 * `runSamples` for every job of one check, in two passes: each job first
 * runs under its own short slice, then the undecided ones share `budget`
 * (a fresh `regexBudget()` when not given). A job left out of the second
 * pass because the budget ran out keeps what its first pass showed, with
 * reason `budget`.
 */
export function runSampleBatch(
  jobs: readonly SampleJob[],
  opts: { budget?: RegexBudget; firstPassMs?: number } = {},
): SampleRun[] {
  const budget = opts.budget ?? regexBudget();
  const slice = opts.firstPassMs ?? REGEX_FIRST_PASS_MS;
  const started = performance.now();
  // past FIRST_PASS_TOTAL_MS the slices shrink: a catch-all still needs far less
  const runs = jobs.map(j => run(j.re, j.samples, {
    untilMiss: j.untilMiss,
    budgetMs: performance.now() - started < FIRST_PASS_TOTAL_MS ? slice : Math.min(slice, 1),
  }, false));
  jobs.forEach((j, k) => {
    const first = runs[k];
    if (first.complete || (j.untilMiss && first.hits.every(Boolean))) return;
    if (budget.remainingMs <= 0) {
      const alt = linearAlternativeHits(j.re, clip(j.samples));
      runs[k] = { hits: first.hits.map((h, i) => h || alt[i]), complete: false, reason: 'budget' };
      return;
    }
    const second = runSamples(j.re, j.samples, { untilMiss: j.untilMiss, budget });
    runs[k] = second.complete
      ? second
      : { hits: second.hits.map((h, i) => h || first.hits[i]), complete: false, reason: second.reason };
  });
  return runs;
}
