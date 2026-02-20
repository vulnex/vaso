import type { CheckResult, Grade } from './types.js';

const CRITICAL_PENALTY = 12;
const WARNING_PENALTY = 5;
const BASE_SCORE = 100;

export function computeScore(results: CheckResult[]): number {
  let score = BASE_SCORE;

  for (const result of results) {
    if (result.passed) continue;

    switch (result.severity) {
      case 'critical':
        score -= CRITICAL_PENALTY;
        break;
      case 'warning':
        score -= WARNING_PENALTY;
        break;
      // info findings don't affect score
    }
  }

  return Math.max(0, Math.min(100, score));
}

export function scoreToGrade(score: number): Grade {
  if (score >= 90) return 'A';
  if (score >= 80) return 'B';
  if (score >= 70) return 'C';
  if (score >= 60) return 'D';
  return 'F';
}

export function summarizeResults(results: CheckResult[]) {
  let critical = 0;
  let warning = 0;
  let info = 0;
  let passed = 0;

  for (const result of results) {
    if (result.passed) {
      passed++;
    } else {
      switch (result.severity) {
        case 'critical':
          critical++;
          break;
        case 'warning':
          warning++;
          break;
        case 'info':
          info++;
          break;
      }
    }
  }

  return { critical, warning, info, passed, total: results.length };
}
