import { describe, it, expect } from 'vitest';
import { computeScore, scoreToGrade, summarizeResults } from './scoring.js';
import type { CheckResult } from './types.js';

function makeResult(overrides: Partial<CheckResult> = {}): CheckResult {
  return {
    id: 'TEST-001',
    name: 'Test Check',
    category: 'config',
    severity: 'warning',
    passed: true,
    message: 'All good',
    ...overrides,
  };
}

describe('computeScore', () => {
  it('returns 100 for all passed checks', () => {
    const results = [makeResult(), makeResult(), makeResult()];
    expect(computeScore(results)).toBe(100);
  });

  it('deducts 12 per critical failure', () => {
    const results = [
      makeResult({ passed: false, severity: 'critical' }),
    ];
    expect(computeScore(results)).toBe(88);
  });

  it('deducts 5 per warning failure', () => {
    const results = [
      makeResult({ passed: false, severity: 'warning' }),
    ];
    expect(computeScore(results)).toBe(95);
  });

  it('does not deduct for info failures', () => {
    const results = [
      makeResult({ passed: false, severity: 'info' }),
    ];
    expect(computeScore(results)).toBe(100);
  });

  it('handles mixed results', () => {
    const results = [
      makeResult({ passed: false, severity: 'critical' }),
      makeResult({ passed: false, severity: 'warning' }),
      makeResult({ passed: true }),
    ];
    // 100 - 12 - 5 = 83
    expect(computeScore(results)).toBe(83);
  });

  it('floors at 0', () => {
    const results = Array.from({ length: 10 }, () =>
      makeResult({ passed: false, severity: 'critical' })
    );
    // 100 - 120 = 0 (clamped)
    expect(computeScore(results)).toBe(0);
  });

  it('handles empty results', () => {
    expect(computeScore([])).toBe(100);
  });
});

describe('scoreToGrade', () => {
  it('grades correctly', () => {
    expect(scoreToGrade(100)).toBe('A');
    expect(scoreToGrade(95)).toBe('A');
    expect(scoreToGrade(90)).toBe('A');
    expect(scoreToGrade(89)).toBe('B');
    expect(scoreToGrade(80)).toBe('B');
    expect(scoreToGrade(79)).toBe('C');
    expect(scoreToGrade(70)).toBe('C');
    expect(scoreToGrade(69)).toBe('D');
    expect(scoreToGrade(60)).toBe('D');
    expect(scoreToGrade(59)).toBe('F');
    expect(scoreToGrade(0)).toBe('F');
  });
});

describe('summarizeResults', () => {
  it('counts correctly', () => {
    const results = [
      makeResult({ passed: false, severity: 'critical' }),
      makeResult({ passed: false, severity: 'critical' }),
      makeResult({ passed: false, severity: 'warning' }),
      makeResult({ passed: false, severity: 'info' }),
      makeResult({ passed: true }),
      makeResult({ passed: true }),
    ];
    const summary = summarizeResults(results);
    expect(summary).toEqual({
      critical: 2,
      warning: 1,
      info: 1,
      passed: 2,
      total: 6,
    });
  });

  it('handles empty', () => {
    expect(summarizeResults([])).toEqual({
      critical: 0,
      warning: 0,
      info: 0,
      passed: 0,
      total: 0,
    });
  });
});
