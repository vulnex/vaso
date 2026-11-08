import { describe, it, expect } from 'vitest';
import { unsafeRegexReason, ruleInput, MAX_RULE_INPUT } from './regex-safety.js';

describe('unsafeRegexReason', () => {
  it.each([
    '(a+)+$',
    '(a*)*b',
    '(\\w+\\s?)*$',
    '(.*a){12}',
    '(?:x+y?)+z',
    '(a{1,5})+$',
    '(a|ab)*c',
    '(\\w|\\d)+!',
    '(?:[a-z]|[a-f0-9])+$',
    '\\d+\\d+x',
    '.*.*=',
    '\\w*\\s?\\w+!',
    '^(([a-z])+.)+[A-Z]([a-z])+$',
    '(?=(a+)+b)',
    'x(?:(?:a+)+)y',
    // bounded repeats of a variable-length group: 25^25 / 2^25 ways to split the input
    '(a{1,25}){1,25}$',
    '(a{1,30}){1,30}$',
    '(a?){25}a{25}',
  ])('rejects %s', (re) => {
    expect(unsafeRegexReason(re)).toBeDefined();
  });

  it.each([
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
  ])('accepts %s', (re) => {
    expect(unsafeRegexReason(re)).toBeUndefined();
  });

  it('rejects what it cannot parse', () => {
    expect(unsafeRegexReason('(?<x')).toBeDefined();
  });
});

describe('ruleInput', () => {
  it('caps the text a rule regex runs on', () => {
    expect(ruleInput('x'.repeat(MAX_RULE_INPUT + 10))).toHaveLength(MAX_RULE_INPUT);
    expect(ruleInput('short')).toBe('short');
  });
});
