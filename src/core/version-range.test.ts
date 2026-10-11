import { describe, it, expect } from 'vitest';
import { exactVersion, rangeBounds, rangeEntirelyAffected } from './version-range.js';

describe('rangeBounds', () => {
  it.each([
    ['^1.2.3', { min: '1.2.3', maxExclusive: '2.0.0' }],
    ['^0.5.0', { min: '0.5.0', maxExclusive: '0.6.0' }],
    ['^0.0.3', { min: '0.0.3', maxExclusive: '0.0.4' }],
    ['~1.2.3', { min: '1.2.3', maxExclusive: '1.3.0' }],
    ['1.x', { min: '1.0.0', maxExclusive: '2.0.0' }],
    ['1.2.x', { min: '1.2.0', maxExclusive: '1.3.0' }],
    ['>=1.0.0 <1.5.0', { min: '1.0.0', maxExclusive: '1.5.0' }],
    ['1.2.3', { min: '1.2.3', maxInclusive: '1.2.3' }],
  ])('npm %s', (range, bounds) => {
    expect(rangeBounds(range, 'npm')).toEqual(bounds);
  });

  it.each([
    ['==1.2.3', { min: '1.2.3', maxInclusive: '1.2.3' }],
    ['>=1.0,<1.5', { min: '1.0.0', maxExclusive: '1.5.0' }],
    ['~=1.2', { min: '1.2.0', maxExclusive: '2.0.0' }],
    ['~=1.2.3', { min: '1.2.3', maxExclusive: '1.3.0' }],
    ['<1.9', { min: '0.0.0', maxExclusive: '1.9.0' }],
    ['>=1.2,!=1.3.0', { min: '1.2.0' }],
  ])('pypi %s', (range, bounds) => {
    expect(rangeBounds(range, 'pypi')).toEqual(bounds);
  });

  it.each(['*', 'latest', '^1.0.0 || ^2.0.0', 'workspace:*', 'file:../sdk', 'github:org/repo'])('has no bounds for %s', (range) => {
    expect(rangeBounds(range, 'npm')).toBeUndefined();
  });
});

describe('rangeEntirelyAffected', () => {
  it('flags a range that admits no fixed release (appsecco outdated-packages ^0.5.0)', () => {
    expect(rangeEntirelyAffected('^0.5.0', 'npm', '<1.24.0', '1.24.0')).toBe(true);
  });

  it('does not flag a range that admits the fix', () => {
    expect(rangeEntirelyAffected('^1.0.4', 'npm', '<1.24.0', '1.24.0')).toBe(false);
  });

  it('does not flag a range starting below the affected window', () => {
    expect(rangeEntirelyAffected('^0.5.0', 'npm', '>=1.3.0 <1.25.2', '1.25.2')).toBe(false);
  });

  it('handles PyPI upper bounds and open ranges', () => {
    expect(rangeEntirelyAffected('>=1.0,<1.9', 'pypi', '<1.9.4', '1.9.4')).toBe(true);
    expect(rangeEntirelyAffected('>=1.0', 'pypi', '<1.9.4', '1.9.4')).toBe(false);
  });
});

describe('exactVersion', () => {
  it.each([['1.2.3', '1.2.3'], ['==1.9', '1.9.0'], ['=2.0.0', '2.0.0'], ['^1.2.3', undefined], ['>=1.0', undefined]])('%s', (spec, version) => {
    expect(exactVersion(spec)).toBe(version);
  });
});
