import { describe, it, expect } from 'vitest';
import { levenshteinDistance, detectTyposquatting } from './typosquat.js';

describe('levenshteinDistance', () => {
  it('returns 0 for identical strings', () => {
    expect(levenshteinDistance('hello', 'hello')).toBe(0);
  });

  it('returns length of non-empty string when other is empty', () => {
    expect(levenshteinDistance('', 'abc')).toBe(3);
    expect(levenshteinDistance('abc', '')).toBe(3);
  });

  it('returns 1 for single substitution', () => {
    expect(levenshteinDistance('cat', 'car')).toBe(1);
  });

  it('returns 1 for single insertion', () => {
    expect(levenshteinDistance('cat', 'cats')).toBe(1);
  });

  it('returns 1 for single deletion', () => {
    expect(levenshteinDistance('cats', 'cat')).toBe(1);
  });

  it('handles multi-edit distances', () => {
    expect(levenshteinDistance('kitten', 'sitting')).toBe(3);
  });
});

describe('detectTyposquatting', () => {
  const trusted = ['filesystem', 'web-search', 'calculator', 'weather'];

  it('detects typosquat with distance 1', () => {
    const result = detectTyposquatting('filesystam', trusted);
    expect(result).not.toBeNull();
    expect(result!.trustedName).toBe('filesystem');
    expect(result!.distance).toBe(1);
  });

  it('detects typosquat with distance 2', () => {
    const result = detectTyposquatting('calculater', trusted);
    expect(result).not.toBeNull();
    expect(result!.trustedName).toBe('calculator');
  });

  it('returns null for exact match', () => {
    const result = detectTyposquatting('filesystem', trusted);
    expect(result).toBeNull();
  });

  it('returns null for distant names', () => {
    const result = detectTyposquatting('completely-different', trusted);
    expect(result).toBeNull();
  });

  it('normalizes hyphens and underscores', () => {
    const result = detectTyposquatting('web_search', trusted);
    // After normalization, 'websearch' === 'websearch', so it's an exact match = null
    expect(result).toBeNull();
  });

  it('detects subtle typosquats', () => {
    const result = detectTyposquatting('weathr', trusted);
    expect(result).not.toBeNull();
    expect(result!.trustedName).toBe('weather');
  });
});
