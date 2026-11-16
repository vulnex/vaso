import { createContext, runInContext, type Context } from 'node:vm';
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
 * limit is hit the result is undefined — "not evaluated", which callers
 * report rather than read as "doesn't match".
 */

/** Time limit for one pattern over all its samples. */
export const REGEX_SAMPLE_BUDGET_MS = 250;

/** Longest sample text; the samples are short commands and paths. */
const MAX_SAMPLE_LENGTH = 512;

let sandbox: Context | undefined;

/**
 * Whether `re` matches each sample (`re.test`), or undefined when it ran out
 * of time. With `untilMiss` the samples are tried in order and the first
 * miss ends the run (the rest read as misses): a caller asking "does it
 * match all of these" passes the shortest samples first, so a pattern that
 * fails is told apart before it can backtrack on a long one.
 */
export function testSamples(re: RegExp, samples: readonly string[], opts: { untilMiss?: boolean; budgetMs?: number } = {}): boolean[] | undefined {
  const texts = samples.map(s => (s.length > MAX_SAMPLE_LENGTH ? s.slice(0, MAX_SAMPLE_LENGTH) : s));
  const untilMiss = !!opts.untilMiss;
  if (!unsafeRegexReason(re.source)) {
    const plain = new RegExp(re.source, re.flags.replace(/[gy]/g, ''));
    let missed = false;
    return texts.map(t => !(missed && untilMiss) && (plain.test(t) || ((missed = true), false)));
  }
  sandbox ??= createContext(Object.create(null));
  sandbox.source = re.source;
  sandbox.flags = re.flags.replace(/[gy]/g, '');
  sandbox.texts = texts;
  sandbox.untilMiss = untilMiss;
  try {
    const out = runInContext(
      '(() => { const r = new RegExp(source, flags); let missed = false; return texts.map(t => !(missed && untilMiss) && (r.test(t) || ((missed = true), false))); })()',
      sandbox,
      { timeout: opts.budgetMs ?? REGEX_SAMPLE_BUDGET_MS },
    ) as unknown;
    return Array.isArray(out) ? out.map(Boolean) : undefined;
  } catch {
    return undefined;
  } finally {
    sandbox.texts = undefined;
  }
}
