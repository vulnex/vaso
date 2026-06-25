import { describe, it, expect } from 'vitest';
import { computeScore, scoreToGrade, summarizeResults, aggregateScore, meanScore } from './scoring.js';
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
    const score = computeScore(results);
    console.log(`[computeScore] 3 passed checks → score: ${score}`);
    expect(score).toBe(100);
  });

  it('deducts 12 per critical failure', () => {
    const results = [
      makeResult({ passed: false, severity: 'critical' }),
    ];
    const score = computeScore(results);
    console.log(`[computeScore] 1 critical failure → score: ${score} (100 - 12)`);
    expect(score).toBe(88);
  });

  it('deducts 5 per warning failure', () => {
    const results = [
      makeResult({ passed: false, severity: 'warning' }),
    ];
    const score = computeScore(results);
    console.log(`[computeScore] 1 warning failure → score: ${score} (100 - 5)`);
    expect(score).toBe(95);
  });

  it('does not deduct for info failures', () => {
    const results = [
      makeResult({ passed: false, severity: 'info' }),
    ];
    const score = computeScore(results);
    console.log(`[computeScore] 1 info failure → score: ${score} (no deduction)`);
    expect(score).toBe(100);
  });

  it('handles mixed results', () => {
    const results = [
      makeResult({ passed: false, severity: 'critical' }),
      makeResult({ passed: false, severity: 'warning' }),
      makeResult({ passed: true }),
    ];
    const score = computeScore(results);
    console.log(`[computeScore] 1 critical + 1 warning + 1 pass → score: ${score} (100 - 12 - 5)`);
    expect(score).toBe(83);
  });

  it('floors at 0', () => {
    const results = Array.from({ length: 10 }, () =>
      makeResult({ passed: false, severity: 'critical' })
    );
    const score = computeScore(results);
    console.log(`[computeScore] 10 critical failures → score: ${score} (clamped from ${100 - 120})`);
    expect(score).toBe(0);
  });

  it('handles empty results', () => {
    const score = computeScore([]);
    console.log(`[computeScore] empty results → score: ${score}`);
    expect(score).toBe(100);
  });
});

describe('scoreToGrade', () => {
  it('grades correctly', () => {
    const grades = [100, 95, 90, 89, 80, 79, 70, 69, 60, 59, 0].map(s => ({
      score: s,
      grade: scoreToGrade(s),
    }));
    console.log('[scoreToGrade] mappings:', grades.map(g => `${g.score}→${g.grade}`).join(', '));
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
    console.log('[summarizeResults] 6 results →', JSON.stringify(summary));
    expect(summary).toEqual({
      critical: 2,
      warning: 1,
      info: 1,
      passed: 2,
      total: 6,
    });
  });

  it('handles empty', () => {
    const summary = summarizeResults([]);
    console.log('[summarizeResults] empty →', JSON.stringify(summary));
    expect(summary).toEqual({
      critical: 0,
      warning: 0,
      info: 0,
      passed: 0,
      total: 0,
    });
  });
});

describe('aggregateScore (headline = worst-case)', () => {
  it('returns the lowest agent score, not the mean', () => {
    // A clean fleet must not mask one wide-open agent.
    expect(aggregateScore([0, 100, 100, 100, 100])).toBe(0);
  });

  it('equals the score for a single agent', () => {
    expect(aggregateScore([75])).toBe(75);
  });

  it('returns 100 when no agents are detected (nothing to fault)', () => {
    expect(aggregateScore([])).toBe(100);
  });
});

describe('meanScore (secondary fleet average)', () => {
  it('is the rounded arithmetic mean', () => {
    expect(meanScore([0, 100, 100, 100, 100])).toBe(80);
    expect(meanScore([88, 85])).toBe(87); // rounds
  });

  it('equals the score for a single agent', () => {
    expect(meanScore([75])).toBe(75);
  });

  it('returns 100 when no agents are detected', () => {
    expect(meanScore([])).toBe(100);
  });
});
