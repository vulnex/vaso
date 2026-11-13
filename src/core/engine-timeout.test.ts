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

describe('runCheck snippet cap', () => {
  it('cuts evidence snippets to MAX_SNIPPET and leaves short ones alone', async () => {
    const { runCheck, MAX_SNIPPET } = await import('./engine.js');
    const check = {
      id: 'T-1', name: 't', category: 'config', severity: 'warning', description: 'd',
      run: async () => ({
        id: 'T-1', name: 't', category: 'config', severity: 'warning', passed: false, message: 'm',
        evidence: [{ file: '/a', snippet: 'x '.repeat(1_000_000) }, { file: '/b', snippet: 'short' }],
      }),
    } as unknown as Parameters<typeof runCheck>[0];
    const result = await runCheck(check, {} as Parameters<typeof runCheck>[1], 5_000);
    expect(result.evidence![0].snippet!.length).toBeLessThanOrEqual(MAX_SNIPPET + 4);
    expect(result.evidence![0].snippet!.endsWith(' ...')).toBe(true);
    expect(result.evidence![1].snippet).toBe('short');
  });
});

describe('runCheck evidence cap', () => {
  it('keeps at most MAX_EVIDENCE items and counts the rest in the last one', async () => {
    const { runCheck, MAX_EVIDENCE } = await import('./engine.js');
    const evidence = Array.from({ length: 5000 }, (_, i) => ({ file: `/f${i % 3}`, snippet: `line ${i}` }));
    const check = {
      id: 'T-2', name: 't', category: 'config', severity: 'warning', description: 'd',
      run: async () => ({ id: 'T-2', name: 't', category: 'config', severity: 'warning', passed: false, message: 'Found 5000', evidence }),
    } as unknown as Parameters<typeof runCheck>[0];
    const result = await runCheck(check, {} as Parameters<typeof runCheck>[1], 5_000);
    expect(result.evidence).toHaveLength(MAX_EVIDENCE);
    expect(result.evidence![MAX_EVIDENCE - 1].detail).toContain(`${5000 - MAX_EVIDENCE + 1} more evidence item(s)`);
    expect(result.message).toBe('Found 5000');
  });
});

describe('evidence cap order', () => {
  it('keeps the same items whatever order the check produced them in', async () => {
    const { capSnippets, MAX_EVIDENCE } = await import('./engine.js');
    const items = Array.from({ length: 1000 }, (_, i) => ({ file: `/f${String(i).padStart(4, '0')}`, line: 1 }));
    const base = { id: 'T', name: 't', category: 'config', severity: 'warning', passed: false, message: 'm' } as const;
    const a = capSnippets({ ...base, evidence: items } as never);
    const b = capSnippets({ ...base, evidence: [...items].reverse() } as never);
    expect(a.evidence!.slice(0, MAX_EVIDENCE - 1)).toEqual(b.evidence!.slice(0, MAX_EVIDENCE - 1));
  });
});
