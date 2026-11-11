import { describe, it, expect } from 'vitest';
import { unsafeRegexReason, ruleInput, MAX_RULE_INPUT } from './regex-safety.js';

/** `\b(?:keyword0|keyword1|…)\b`-style lists, the most common rule shape. */
const keywords = (n: number, stem = 'keyword') => Array.from({ length: n }, (_, i) => `${stem}${i}`).join('|');

describe('unsafeRegexReason', () => {
  it.each([
    '(a+)+$',
    '(a*)*b',
    '(\\w+\\s?)*$',
    '(.*a){12}',
    '(?:x+y?)+z',
    '(a{1,5})+$',
    '(\\w|\\d)+!',
    '(?:[a-z]|[a-f0-9])+$',
    // two overlapping loops plus the search over start positions: n^3
    // (each ~10 s on a 4 KB line)
    '\\d+\\d+x',
    '.*.*=',
    '\\w*\\s?\\w+!',
    // ~1.5 s on `password` × 512: drop the leading `.*` or anchor it with `^`
    '.*(password|secret).*=',
    '.{0,200}x.{0,200}y',
    '(.*)*x',
    // three loops even when anchored: ~1.5 s on `${}`… with a newline in a value
    '^.*\\$\\{.*\\}.*$',
    // dt20 g8-R1: characters outside Latin-1 (UTF-16 code units, no `u` flag)
    '(?:’|’’)+$',
    '(?:丁|丁丁)+$',
    '(?:[一-丅]|丁)+$',
    '(?:[^a]|丁)+$',
    '(?:[一-鿿]+[丁]+)+$',
    '(?:😀|\\ud83d.)+$',
    '(?:[\\u4e00-\\u4e05]|\\u4e01)+$',
    '(?:\\s|\\u3000)+$',
    // a loop behind an assertion that can still fail hasn't matched (26 s on a×4096)
    '.*a.*(?=x)',
    '^(([a-z])+.)+[A-Z]([a-z])+$',
    '(?=(a+)+b)',
    'x(?:(?:a+)+)y',
    // bounded repeats of a variable-length group: 25^25 / 2^25 ways to split the input
    '(a{1,25}){1,25}$',
    '(a{1,30}){1,30}$',
    '(a?){25}a{25}',
    // dt20: overlapping unbounded atoms with mandatory atoms between them
    '.*a.*a.*a.*a.*b',
    '\\w*a\\w*a\\w*a\\w*b',
    '[^b]*a[^b]*a[^b]*a[^b]*b',
    '.*ab.*ab.*c',
    // overlapping alternatives one group down, or in an optional inner group
    '(?:(?:a|aa))+$',
    '(?:(a|aa))+$',
    '(?:a(?:a|aa)?)+$',
    // unbounded groups in a row, finite splits multiplied across a sequence
    '(?:a*)(?:a*)(?:a*)(?:a*)c',
    '(a{1,4}){4}(a{1,4}){4}(a{1,4}){4}$',
    `${'(a|a)?'.repeat(20)}a{20}$`,
    '\\w+\\w{0,6}!',
    // dt21 g8-F1: `\c` without a control letter is a backslash, then `c`
    '(?:\\\\\\c|\\\\\\\\c)+$',
    '(?:\\c|\\\\c)+$',
    '(?:\\c_|\\\\c_)+$',
    // dt21 g8-F2: `[^]` is any character and `[]` nothing (not PCRE's `[^]…]`)
    '(?:[^]=]|\\w=])+$',
    '(?:[^]a]|.a])+$',
    '[^]*[^]*[^]*x',
    '.*[^]*.*x',
    // dt21 g8-F3: a lookahead body backtracks from every place it runs
    // (`.+(?=.*=)`: ~31 s on a 4 KB line)
    '.+(?=.*=)',
    '\\w+(?=\\w*!)',
    '[a-z]+(?=[a-z]*=)',
    '(?:a(?=\\w*!))+$',
    // … and a lookbehind body, right to left (`(?<=(?=\w*!)\w*)`: 9 s on 2 KB)
    '(?<=(?=\\w*!)\\w*)',
    '\\w+(?<=!\\w*)',
    // a negative lookahead whose body can succeed (3.9 s on `a`×4095 + `!`)
    '\\w+(?!\\w*!)',
    // dt21 g8-F4: a backreference reads what its group read (`(.*)\1x`: n^3)
    '(.*)\\1x',
    '(\\w*)\\1x',
    '(.*)\\1\\1\\1\\1x',
    `(.*)${'\\1'.repeat(64)}x`,
    '(.+)\\1{100}x',
    '(?<n>\\w*)\\k<n>x',
    '(?=(\\w*)\\1!)',
    // a group that may not have matched: its backreference may read nothing
    '(x)?(?:\\1a|a)+$',
    '()(?:\\1a|a)+$',
  ])('rejects %s', (re) => {
    expect(unsafeRegexReason(re)).toBeDefined();
  });

  const ACCEPTED = [
    'AKIA[0-9A-Z]{16}',
    'API_KEY|api_key',
    'password\\s*[:=]\\s*\\S+',
    '"api_key"\\s*:\\s*"[^"]+"',
    '^\\s*#',
    'sk-[A-Za-z0-9]{20,}',
    '(?:foo|bar)+',
    '(ab)+c',
    '(ab?)+c',
    '\\bdebug\\s*=\\s*true\\b',
    '\\s*\\w+=',
    '[a-z]+\\d+',
    '(?:https?|ftp)://[^\\s/]+',
    '\\{\\{\\w+\\}\\}',
    'a{2}b{3,}',
    '(\\d{1,3}\\.){3}\\d{1,3}',
    '([a-z]{1,8}\\.){1,4}[a-z]{2,6}',
    '(\\w{2,4}-){10}',
    '^(foo|bar){2}$',
    // alternatives share a first character but never the same text
    '(a|ab)*c',
    // dt20 (g8-F7): linear patterns the old syntactic screen rejected
    '^(?:[a-z0-9-]+\\.)+[a-z]{2,}$',
    '(?:[A-Z][a-z]+)+',
    '(?:\\w+\\.)+(?:com|net)',
    '^(?:/[^/]+)+$',
    '(?:\\d+,)*\\d+',
    'v?\\d+(?:\\.\\d+)*',
    '(?:"[^"]*",\\s*)*"[^"]*"',
    'localhost|127\\.0\\.0\\.1',
    '[a-z]{20,}\\d+',
    '.*=',
    // a loop reached only once the pattern has matched costs nothing
    '.*password.*',
    '^.*\\bpassword\\b.*$',
    '(password|secret).*=',
    '^.*(password|secret).*=',
    // anchored, or behind a literal: two loops are n^2 at most
    '^\\d+\\d+x',
    'x\\d+\\d+y',
    // keyword lists: alternatives sharing a prefix are not ambiguity
    `\\b(?:${keywords(10)})\\b`,
    `\\b(?:${keywords(100)})\\b`,
    `\\b(?:${keywords(300)})\\b`,
    `.*\\b(?:${keywords(50, 'secret_')})\\b`,
    `(?:${keywords(300, 'k')})\\s*=`,
    '[a-z0-9]{0,999}',
    '"(?:[^"\\\\]|\\\\.)*"',
    '[^=]*=[^=]*=x',
    // non-ASCII
    '[一-鿿]+',
    '’[^’]*’',
    '\\p{L}+',
    '[\\u4e00-\\u9fff]+\\s*=',
    '😀+x',
    // dt21 g8: a sweep of realistic rule shapes
    '["\']?(?:api[_-]?key|token)["\']?\\s*[:=]\\s*["\']?[A-Za-z0-9_\\-]{16,}',
    'https?://[^\\s/]+(?:/[^\\s]*)?',
    '\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b',
    '[A-Za-z0-9+/]{40,}={0,2}',
    '-----BEGIN [A-Z ]+PRIVATE KEY-----',
    '^\\s*#.*$',
    '\\$\\{[^}]+\\}',
    '[\\w.+-]+@[\\w-]+\\.[\\w.]+',
    '^\\s*"?allow"?\\s*:\\s*\\[.*\\*.*\\]',
    '(?:password|passwd|pwd)\\s*[=:]\\s*\\S+',
    '[a-f0-9]{32,64}',
    '(?:\\.\\./)+',
    '^(?:\\s*-\\s*)?\\w+:\\s*.*$',
    // lookarounds with one loop in front of them at most
    '\\bnpx\\s+(?:-y\\s+)?[\\w@/.-]+(?!@\\d)',
    'token(?=.*secret)',
    '(?=\\w*!)',
    '\\w(?=\\w*!)',
    '(?<=\\w*)x',
    '(?<=!\\w*)x',
    '(?<=\\w+)\\w*!',
    '(?<=!\\w*)\\w+',
    '\\w(?<=!\\w*)',
    // dt21 g8-R: a lookbehind of optional single characters reads once
    'x(?<=\\w*\\w*)',
    'x(?<!\\s*[a-z]?\\d*)',
    '\\w+(?<=a)',
    // backreferences to a short or delimiting group
    '([\'"]).*?\\1',
    '(\\w+)\\s*=\\s*\\1',
    '(\\w+)=\\1',
    '(.+)\\1',
    '(\\w{1,4})\\1',
    '^(.*)\\1$',
    '(?:(.)\\1)*x',
    '(.)\\1{3,}',
    // JavaScript classes and Annex B escapes
    'a[]b',
    'x[^]{0,3}y',
    '\\cA+x',
    '\\c+x',
    '(a)\\10',
  ];

  it.each(ACCEPTED)('accepts %s', (re) => {
    expect(unsafeRegexReason(re)).toBeUndefined();
  });

  /**
   * Adversarial 4 KB inputs with no final match: each character of the
   * pattern (and some common ones) repeated, alone and in pairs, and each
   * literal word of the pattern repeated (`passwordpassword…`).
   */
  function adversarialInputs(source: string): string[] {
    const fill = (unit: string) => unit.repeat(Math.floor((MAX_RULE_INPUT - 1) / unit.length)).padEnd(MAX_RULE_INPUT - 1, ' ') + '\u0001';
    const chars = [...new Set([...source.replace(/\\[a-zA-Z]/g, ''), ...'aA0 .-"/,=_'])].filter(c => c >= ' ' && c !== '\x7f');
    const out: string[] = [];
    for (const c of chars) out.push(fill(c));
    for (const c of chars) for (const d of chars) if (c < d) out.push(fill(c + d));
    const words = [...new Set(source.split(/[^A-Za-z0-9_]+/).filter(w => w.length > 1))].slice(0, 20);
    for (const w of words) out.push(fill(w), fill(`${w} `), fill(`${w}=`));
    return out;
  }

  it('every accepted pattern runs fast on adversarial 4 KB inputs', () => {
    const slow: string[] = [];
    for (const source of ACCEPTED) {
      const re = new RegExp(source);
      for (const input of adversarialInputs(source)) {
        const t = performance.now();
        re.exec(input);
        const ms = performance.now() - t;
        if (ms >= 200) slow.push(`${source} on ${JSON.stringify(input.slice(0, 8))}…: ${ms.toFixed(0)} ms`);
      }
    }
    expect(slow).toEqual([]);
  }, 60_000);

  it('reads escapes and classes the way V8 does without the `u` flag (Annex B)', () => {
    // each alternative reads the same text: exponential, not an empty loop
    for (const re of [
      '(?:\\\\\\c|\\\\\\\\c)+$', // `\c` = backslash, `c`
      '(?:\\c_|\\\\c_)+$',
      '(?:[^]=]|\\w=])+$', // `[^]` = any character, then `=]`
      '(?:\\8|8)+$', // `\8` = `8`
      '(a)(?:\\10|\\x08)+$', // `\10` with one group = octal 10
      '(?:\\0|\\x00)+$',
      '(?:\\k|k)+$', // no named groups: `\k` = `k`
      '(?:\\k<n>|k<n>)+$',
    ]) expect(unsafeRegexReason(re), re).toMatch(/exponentially/);
    // with named groups `\k<n>` is a backreference
    expect(unsafeRegexReason('(?<n>a)(?:\\k<n>b|ab)+$')).toMatch(/exponentially/);
    expect(unsafeRegexReason('(?<n>a)\\k<x>')).toMatch(/could not be analysed/);
  });

  it('rejects what it cannot parse', () => {
    expect(unsafeRegexReason('(?<x')).toBeDefined();
  });

  it('rejects patterns too large to analyse', () => {
    expect(unsafeRegexReason('(?:[a-c][d-f]?){20000}')).toMatch(/too large/);
  });

  it('rejects a repeated group that can match empty text', () => {
    expect(unsafeRegexReason('(a|b?)+c')).toMatch(/empty/);
  });

  it('follows modifier groups (Node 23+), case-insensitively', () => {
    expect(unsafeRegexReason('(?i:password)\\s*=')).toBeUndefined();
    expect(unsafeRegexReason('(?i:(?:a|A)+)$')).toMatch(/exponentially/);
  });
});

describe('ruleInput', () => {
  it('caps the text a rule regex runs on', () => {
    expect(ruleInput('x'.repeat(MAX_RULE_INPUT + 10))).toHaveLength(MAX_RULE_INPUT);
    expect(ruleInput('short')).toBe('short');
  });
});
