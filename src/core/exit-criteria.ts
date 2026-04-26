import type { CheckResult, Severity } from './types.js';

export type FailOnLevel = 'critical' | 'warning' | 'info' | 'none';

export const FAIL_ON_LEVELS: readonly FailOnLevel[] = ['critical', 'warning', 'info', 'none'] as const;

const SEVERITY_RANK: Record<Severity, number> = {
  info: 1,
  warning: 2,
  critical: 3,
};

export function isValidFailOn(value: string): value is FailOnLevel {
  return (FAIL_ON_LEVELS as readonly string[]).includes(value);
}

/**
 * Returns true if any failing result meets or exceeds the threshold.
 * `none` always returns false (exit-code escalation disabled).
 */
export function shouldFailScan(results: readonly CheckResult[], failOn: FailOnLevel): boolean {
  if (failOn === 'none') return false;
  const threshold = SEVERITY_RANK[failOn];
  for (const r of results) {
    if (r.passed) continue;
    if (SEVERITY_RANK[r.severity] >= threshold) return true;
  }
  return false;
}
