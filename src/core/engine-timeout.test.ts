import { describe, it, expect } from 'vitest';
import { checkTimeoutFromEnv, DEFAULT_CHECK_TIMEOUT_MS, MAX_CHECK_TIMEOUT_SEC } from './engine.js';

describe('VASO_CHECK_TIMEOUT', () => {
  const run = (v: string | undefined) => {
    const warnings: string[] = [];
    return { ms: checkTimeoutFromEnv(v === undefined ? {} : { VASO_CHECK_TIMEOUT: v }, m => warnings.push(m)), warnings };
  };

  it('uses the default when unset or empty, without a warning', () => {
    expect(run(undefined)).toEqual({ ms: DEFAULT_CHECK_TIMEOUT_MS, warnings: [] });
    expect(run('')).toEqual({ ms: DEFAULT_CHECK_TIMEOUT_MS, warnings: [] });
  });

  it('takes a positive number of seconds', () => {
    expect(run('2').ms).toBe(2000);
    expect(run('0.5').ms).toBe(500);
  });

  it('caps huge values at 24 h instead of overflowing the timer (dt17)', () => {
    for (const v of ['1e9', '99999999999']) {
      const r = run(v);
      expect(r.ms).toBe(MAX_CHECK_TIMEOUT_SEC * 1000);
      expect(r.warnings[0]).toContain('exceeds');
    }
  });

  it('names an unusable value instead of ignoring it silently', () => {
    for (const v of ['abc', '0', '-5']) {
      const r = run(v);
      expect(r.ms).toBe(DEFAULT_CHECK_TIMEOUT_MS);
      expect(r.warnings[0]).toContain('not a positive number');
    }
  });
});
