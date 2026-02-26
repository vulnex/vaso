import { describe, it, expect } from 'vitest';
import { parseSemVer, compareSemVer, satisfies } from './semver.js';

describe('parseSemVer', () => {
  it('parses basic versions', () => {
    expect(parseSemVer('1.2.3')).toEqual({
      major: 1, minor: 2, patch: 3, prerelease: undefined, raw: '1.2.3',
    });
  });

  it('parses v-prefixed versions', () => {
    expect(parseSemVer('v1.2.3')).toEqual({
      major: 1, minor: 2, patch: 3, prerelease: undefined, raw: 'v1.2.3',
    });
  });

  it('parses versions with prerelease', () => {
    const result = parseSemVer('v1.2.3-beta.1');
    expect(result).toEqual({
      major: 1, minor: 2, patch: 3, prerelease: 'beta.1', raw: 'v1.2.3-beta.1',
    });
  });

  it('returns null for invalid versions', () => {
    expect(parseSemVer('not-a-version')).toBeNull();
    expect(parseSemVer('')).toBeNull();
    expect(parseSemVer('1.2')).toBeNull();
  });

  it('trims whitespace', () => {
    expect(parseSemVer('  1.0.0  ')?.major).toBe(1);
  });

  it('parses version with trailing text', () => {
    expect(parseSemVer('1.2.3-rc.1+build.123')?.prerelease).toBe('rc.1');
  });
});

describe('compareSemVer', () => {
  it('compares major versions', () => {
    expect(compareSemVer(parseSemVer('1.0.0')!, parseSemVer('2.0.0')!)).toBe(-1);
    expect(compareSemVer(parseSemVer('2.0.0')!, parseSemVer('1.0.0')!)).toBe(1);
  });

  it('compares minor versions', () => {
    expect(compareSemVer(parseSemVer('1.1.0')!, parseSemVer('1.2.0')!)).toBe(-1);
  });

  it('compares patch versions', () => {
    expect(compareSemVer(parseSemVer('1.0.1')!, parseSemVer('1.0.2')!)).toBe(-1);
  });

  it('returns 0 for equal versions', () => {
    expect(compareSemVer(parseSemVer('1.2.3')!, parseSemVer('1.2.3')!)).toBe(0);
  });

  it('prerelease < release', () => {
    expect(compareSemVer(parseSemVer('1.0.0-beta.1')!, parseSemVer('1.0.0')!)).toBe(-1);
    expect(compareSemVer(parseSemVer('1.0.0')!, parseSemVer('1.0.0-beta.1')!)).toBe(1);
  });

  it('compares prerelease segments numerically', () => {
    expect(compareSemVer(parseSemVer('1.0.0-beta.1')!, parseSemVer('1.0.0-beta.2')!)).toBe(-1);
    expect(compareSemVer(parseSemVer('1.0.0-beta.10')!, parseSemVer('1.0.0-beta.2')!)).toBe(1);
  });

  it('compares prerelease segments alphabetically', () => {
    expect(compareSemVer(parseSemVer('1.0.0-alpha')!, parseSemVer('1.0.0-beta')!)).toBe(-1);
  });
});

describe('satisfies', () => {
  it('matches exact version', () => {
    expect(satisfies('1.2.3', '=1.2.3')).toBe(true);
    expect(satisfies('1.2.3', '=1.2.4')).toBe(false);
  });

  it('matches greater-than', () => {
    expect(satisfies('1.3.0', '>1.2.0')).toBe(true);
    expect(satisfies('1.2.0', '>1.2.0')).toBe(false);
  });

  it('matches greater-than-or-equal', () => {
    expect(satisfies('1.2.0', '>=1.2.0')).toBe(true);
    expect(satisfies('1.1.9', '>=1.2.0')).toBe(false);
  });

  it('matches less-than', () => {
    expect(satisfies('1.1.0', '<1.2.0')).toBe(true);
    expect(satisfies('1.2.0', '<1.2.0')).toBe(false);
  });

  it('matches less-than-or-equal', () => {
    expect(satisfies('1.2.0', '<=1.2.0')).toBe(true);
    expect(satisfies('1.2.1', '<=1.2.0')).toBe(false);
  });

  it('matches range (AND of comparators)', () => {
    expect(satisfies('1.3.0', '>=1.2.0 <1.5.0')).toBe(true);
    expect(satisfies('1.5.0', '>=1.2.0 <1.5.0')).toBe(false);
    expect(satisfies('1.1.9', '>=1.2.0 <1.5.0')).toBe(false);
  });

  it('handles v-prefixed versions', () => {
    expect(satisfies('v1.3.0', '>=1.2.0 <1.5.0')).toBe(true);
  });

  it('returns false for invalid version', () => {
    expect(satisfies('bad', '>=1.0.0')).toBe(false);
  });

  it('returns false for invalid constraint', () => {
    expect(satisfies('1.0.0', 'bad-constraint')).toBe(false);
  });

  it('bare version acts as exact match', () => {
    expect(satisfies('1.2.3', '1.2.3')).toBe(true);
    expect(satisfies('1.2.4', '1.2.3')).toBe(false);
  });
});
