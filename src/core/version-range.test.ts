import { describe, it, expect } from 'vitest';
import { exactVersion, fullVersion, rangeBounds, rangeEntirelyAffected } from './version-range.js';
import { satisfies } from './semver.js';

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

describe('rangeEntirelyAffected with || branches', () => {
  const axios = '<0.30.0 || >=1.0.0 <1.8.2';
  it('judges a range against the branch it falls in, bounded by that branch', () => {
    expect(rangeEntirelyAffected('~0.21.1', 'npm', axios, '0.30.0, 1.8.2')).toBe(true);
    expect(rangeEntirelyAffected('~1.7.0', 'npm', axios, '0.30.0, 1.8.2')).toBe(true);
    // ^1.7.0 admits 1.8.2+, which is fixed.
    expect(rangeEntirelyAffected('^1.7.0', 'npm', axios, '0.30.0, 1.8.2')).toBe(false);
    // Spans both release lines' fixes.
    expect(rangeEntirelyAffected('>=0.21.0', 'npm', axios, '0.30.0, 1.8.2')).toBe(false);
  });
  it('treats an inclusive branch top as the last affected release', () => {
    expect(rangeEntirelyAffected('~2.88.0', 'npm', '<=2.88.2 || >=3.0.0 <3.0.1', undefined)).toBe(false);
    expect(rangeEntirelyAffected('>=2.88.0 <=2.88.2', 'npm', '<=2.88.2 || >=3.0.0 <3.0.1', undefined)).toBe(true);
  });
});

describe('dt20 g3-N1: rangeEntirelyAffected without a fixed version', () => {
  it('falls back to the affected range upper bound', () => {
    expect(rangeEntirelyAffected('^0.30.0', 'npm', '>=0.20.0 <=0.39.0', undefined)).toBe(true);
    expect(rangeEntirelyAffected('~1.2.0', 'npm', '>=1.0.0 <1.5.0', undefined)).toBe(true);
    expect(rangeEntirelyAffected('^1.2.0', 'npm', '>=1.0.0 <1.5.0', undefined)).toBe(false);
    expect(rangeEntirelyAffected('>=1.0,<1.4', 'pypi', '<=1.4.0', undefined)).toBe(true);
    // open-ended with no fix: a bounded range never ends at a fix
    expect(rangeEntirelyAffected('^1.0.0', 'npm', '>=0.0.0', undefined)).toBe(false);
  });
});

describe('dt20 g3 re-verify: hyphen ranges', () => {
  it('reads inclusive and partial tops', () => {
    expect(rangeBounds('0.2.20 - 0.2.21')).toEqual({ min: '0.2.20', maxInclusive: '0.2.21' });
    expect(rangeBounds('1.2 - 2.3')).toEqual({ min: '1.2.0', maxExclusive: '2.4.0' });
    expect(rangeBounds('1 - 2')).toEqual({ min: '1.0.0', maxExclusive: '3.0.0' });
  });
});

describe('dt21 g2-R1: a partial npm version is a range', () => {
  it.each([['0.1', undefined], ['=0.1', undefined], ['1', undefined], ['v2.3', undefined], ['==0.1', '0.1.0'], ['===5.3', '5.3.0'], ['0.1.5', '0.1.5']])('%s', (spec, version) => {
    expect(exactVersion(spec)).toBe(version);
  });
});

describe('PEP 440 pre-, dev- and post-releases', () => {
  it('maps the suffixes to semver that sorts like PEP 440', () => {
    expect(fullVersion('1.10.0rc1')).toBe('1.10.0-rc.1');
    expect(fullVersion('2.0b2')).toBe('2.0.0-b.2');
    expect(fullVersion('2.0a1')).toBe('2.0.0-a.1');
    expect(fullVersion('3.1.dev4')).toBe('3.1.0-0.dev.4');
    expect(fullVersion('1.4.post1')).toBe('1.4.0');
    expect(fullVersion('1.4.0-beta.1')).toBe('1.4.0-beta.1');
    expect(fullVersion('1.4.0foo')).toBe('1.4.0foo');
  });

  it('a release candidate is before its release', () => {
    expect(satisfies(fullVersion('1.10.0rc1'), '<1.10.0')).toBe(true);
    expect(satisfies(fullVersion('1.10.0'), '<1.10.0')).toBe(false);
    for (const [lo, hi] of [['1.0.dev1', '1.0a1'], ['1.0a1', '1.0b1'], ['1.0b1', '1.0rc1'], ['1.0rc1', '1.0']]) {
      expect(satisfies(fullVersion(lo!), `<${fullVersion(hi!)}`), `${lo} < ${hi}`).toBe(true);
    }
  });

  it('pins and ranges of pre-releases', () => {
    expect(exactVersion('==1.10.0rc1')).toBe('1.10.0-rc.1');
    expect(rangeBounds('>=1.9.0,<1.10.0rc2', 'pypi')).toEqual({ min: '1.9.0', maxExclusive: '1.10.0-rc.2' });
  });

  it('npm ^0.0.x admits that patch only', () => {
    expect(rangeBounds('^0.0.3')).toEqual({ min: '0.0.3', maxExclusive: '0.0.4' });
  });
});
