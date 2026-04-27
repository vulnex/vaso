import { describe, it, expect } from 'vitest';
import { mapToCvss } from './cvss-mapper.js';
import type { CheckResult } from '../../core/types.js';

function result(overrides: Partial<CheckResult>): CheckResult {
  return {
    id: 'X-001',
    name: 'X',
    category: 'config',
    severity: 'warning',
    passed: false,
    message: 'fail',
    ...overrides,
  };
}

describe('mapToCvss', () => {
  it('coarse-maps critical → 9.0', () => {
    expect(mapToCvss(result({ severity: 'critical' }))).toEqual({ score: 9.0, source: 'severity-mapped' });
  });

  it('coarse-maps warning → 5.0', () => {
    expect(mapToCvss(result({ severity: 'warning' }))).toEqual({ score: 5.0, source: 'severity-mapped' });
  });

  it('coarse-maps info → 2.0', () => {
    expect(mapToCvss(result({ severity: 'info' }))).toEqual({ score: 2.0, source: 'severity-mapped' });
  });

  it('extracts numeric CVSS from evidence detail', () => {
    const r = result({
      severity: 'warning',
      evidence: [{ file: 'CVE-2026-40001', detail: 'gateway bypass, cvss=9.8, exploit available' }],
    });
    expect(mapToCvss(r)).toEqual({ score: 9.8, source: 'real' });
  });

  it('extracts CVSS from "CVSS: N.N" form', () => {
    const r = result({
      severity: 'critical',
      evidence: [{ file: 'CVE-X', detail: 'CVSS: 7.5 — high severity' }],
    });
    expect(mapToCvss(r)).toEqual({ score: 7.5, source: 'real' });
  });

  it('falls back to severity when CVSS value is out of range', () => {
    const r = result({
      severity: 'warning',
      evidence: [{ file: 'X', detail: 'cvss=99.0' }],
    });
    expect(mapToCvss(r)).toEqual({ score: 5.0, source: 'severity-mapped' });
  });

  it('falls back to severity when no evidence present', () => {
    expect(mapToCvss(result({ severity: 'critical', evidence: undefined }))).toEqual({ score: 9.0, source: 'severity-mapped' });
  });

  it('ignores CVSS vector strings without a numeric score', () => {
    const r = result({
      severity: 'info',
      evidence: [{ file: 'x', detail: 'CVSS:3.1/AV:N/AC:L' }],
    });
    expect(mapToCvss(r).source).toBe('severity-mapped');
  });
});
