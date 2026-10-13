import type { CheckResult, Severity } from './types.js';

/** Exit codes: 0 clean · 1 findings at/above --fail-on · 2 invalid usage or
 *  VASO error · 3 scan incomplete (one or more hosts could not be scanned —
 *  takes precedence over 1, so CI can tell "unscanned" from "findings"). */
export const EXIT_FINDINGS = 1;
export const EXIT_USAGE = 2;
export const EXIT_INCOMPLETE = 3;

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

/** The --fail-on level, or undefined (after printing why) when invalid. */
export function parseFailOn(value: string | undefined, fallback: FailOnLevel = 'critical'): FailOnLevel | undefined {
  if (value === undefined) return fallback;
  if (isValidFailOn(value)) return value;
  console.error(`Invalid --fail-on value "${value}". Use: critical, warning, info, or none.`);
  return undefined;
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
