import { describe, it, expect } from 'vitest';
import { compilePyFullmatch, isCatchAllPattern } from './nanobot/nb-004-exec-tool-filter.js';
import { compileGoRegex } from './picoclaw/shared.js';

// Config-supplied regexes are run against sample commands/paths: one that
// backtracks super-linearly is not run at all.
describe('config regexes that backtrack are not run', () => {
  it('nanobot exec patterns', () => {
    expect(compilePyFullmatch('(a+)+$')).toBeUndefined();
    expect(compilePyFullmatch('(.*)*x')).toBeUndefined();
    expect(compilePyFullmatch('.*')).toBeDefined();
    expect(isCatchAllPattern('.*')).toBe(true);
    const start = Date.now();
    expect(isCatchAllPattern('(.*)*x')).toBe(false);
    expect(Date.now() - start).toBeLessThan(500);
  });

  it('picoclaw allow patterns', () => {
    expect(compileGoRegex('(.*)*x')).toBeUndefined();
    expect(compileGoRegex('(?i)^/home/.*')).toBeDefined();
  });
});
