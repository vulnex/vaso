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

/**
 * Headline score across multiple agents: worst-case, not mean.
 *
 * A security posture is gated by its weakest agent — one wide-open agent is a
 * real exposure regardless of how many others are clean. A mean has the wrong
 * failure mode here: it grows *more* reassuring as clean agents are added, so it
 * can bury a critical finding in a large fleet. The mean is still reported, but
 * as a secondary fleet-health metric (`meanScore` / `ScanResult.fleetAverage`),
 * never as the headline. With no agents detected there is nothing to fault, so
 * the posture is a clean 100.
 */
export function aggregateScore(scores: number[]): number {
  if (scores.length === 0) return 100;
  return Math.min(...scores);
}

/** Mean of per-agent scores — fleet-health/trend metric, not the headline. */
export function meanScore(scores: number[]): number {
  if (scores.length === 0) return 100;
  return Math.round(scores.reduce((sum, s) => sum + s, 0) / scores.length);
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
