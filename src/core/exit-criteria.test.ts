import { describe, it, expect } from 'vitest';
import type { CheckResult } from './types.js';
import { shouldFailScan, isValidFailOn, incompleteResults } from './exit-criteria.js';

function r(severity: 'critical' | 'warning' | 'info', passed: boolean): CheckResult {
  return {
    id: 'X',
    name: 'x',
    category: 'config',
    severity,
    passed,
    message: '',
  };
}

describe('shouldFailScan', () => {
  it('returns false on an empty result set regardless of threshold', () => {
    for (const lvl of ['critical', 'warning', 'info'] as const) {
      expect(shouldFailScan([], lvl)).toBe(false);
    }
  });

  it('passing findings never trip the threshold', () => {
    expect(shouldFailScan([r('critical', true), r('warning', true)], 'info')).toBe(false);
  });

  it('critical threshold fails only on critical findings', () => {
    expect(shouldFailScan([r('warning', false)], 'critical')).toBe(false);
    expect(shouldFailScan([r('info', false)], 'critical')).toBe(false);
    expect(shouldFailScan([r('critical', false)], 'critical')).toBe(true);
  });

  it('warning threshold fails on warning or critical', () => {
    expect(shouldFailScan([r('info', false)], 'warning')).toBe(false);
    expect(shouldFailScan([r('warning', false)], 'warning')).toBe(true);
    expect(shouldFailScan([r('critical', false)], 'warning')).toBe(true);
  });

  it('info threshold fails on any failing finding', () => {
    expect(shouldFailScan([r('info', false)], 'info')).toBe(true);
    expect(shouldFailScan([r('warning', false)], 'info')).toBe(true);
    expect(shouldFailScan([r('critical', false)], 'info')).toBe(true);
  });

  it('none threshold never fails, even on critical findings', () => {
    expect(shouldFailScan([r('critical', false), r('warning', false)], 'none')).toBe(false);
  });
});

describe('isValidFailOn', () => {
  it.each(['critical', 'warning', 'info', 'none'])('accepts %s', (v) => {
    expect(isValidFailOn(v)).toBe(true);
  });

  it.each(['CRITICAL', 'fatal', 'high', 'low', '', ' '])('rejects %s', (v) => {
    expect(isValidFailOn(v)).toBe(false);
  });
});

describe('incompleteResults', () => {
  it('an errored check or adapter makes the scan incomplete; CONFIG-LOAD and ordinary findings do not', () => {
    const errored = { ...r('warning', false), id: 'PLG-002', errored: true };
    const detect = { ...r('warning', false), id: 'ADAPTER-DETECT', errored: true };
    const configLoad = { ...r('warning', false), id: 'CONFIG-LOAD', errored: true };
    expect(incompleteResults([errored, detect, configLoad, r('critical', false)]).map(x => x.id)).toEqual(['PLG-002', 'ADAPTER-DETECT']);
    expect(incompleteResults([configLoad, r('critical', false)])).toEqual([]);
  });
});
