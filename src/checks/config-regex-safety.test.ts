import { describe, it, expect } from 'vitest';
import { compilePyFullmatch, isCatchAllPattern, judgeAllowPattern } from './nanobot/nb-004-exec-tool-filter.js';
import { compileGoRegex } from './picoclaw/shared.js';
import { judgeCustomAllow } from './picoclaw/pcl-002-exec-guard.js';
import { testSamples } from '../analyzers/bounded-regex.js';

describe('config regexes that may backtrack are still judged', () => {
  it('nanobot exec patterns: catch-alls the static screen rejects are caught', () => {
    for (const p of ['.*', '(.|\\s)*', '(.+)+', '.*.*.*', '(.|\\n)*', '([\\s\\S])*']) {
      expect(judgeAllowPattern(p), p).toBe('catch-all');
    }
    expect(compilePyFullmatch('(a+)+$')).toBeDefined();
    const start = Date.now();
    expect(isCatchAllPattern('(.*)*x')).toBe(false);
    expect(isCatchAllPattern('(a+)+$')).toBe(false);
    expect(Date.now() - start).toBeLessThan(1000);
  });

  it('picoclaw allow patterns: catch-alls the static screen rejects are caught', () => {
    for (const p of ['(.|\\s)*', '(.+)+', '.*.*.*']) expect(judgeCustomAllow(p), p).toBe('catch-all');
    expect(compileGoRegex('(.*)*x')).toBeDefined();
    expect(compileGoRegex('(?i)^/home/.*')).toBeDefined();
    expect(judgeCustomAllow('^git (status|log)$')).toBeUndefined();
  });

  it('a pattern that runs out of time is not evaluated, never a pass', () => {
    const start = Date.now();
    expect(testSamples(/^(a|aa)+$/, ['a'.repeat(60) + 'b'], { budgetMs: 100 })).toBeUndefined();
    expect(Date.now() - start).toBeLessThan(2000);
    expect(testSamples(/^(a|aa)+$/, ['aaaa', 'b'])).toEqual([true, false]);
    // untilMiss: the first miss ends the run before a long sample can backtrack
    expect(testSamples(/^(a|aa)+$/, ['b', 'a'.repeat(60) + 'b'], { untilMiss: true })).toEqual([false, false]);
  });
});
