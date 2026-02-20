import { describe, it, expect } from 'vitest';
import { levenshteinDistance, detectTyposquatting } from './typosquat.js';

describe('levenshteinDistance', () => {
  it('returns 0 for identical strings', () => {
    const d = levenshteinDistance('hello', 'hello');
    console.log(`[levenshtein] "hello" vs "hello" → distance: ${d}`);
    expect(d).toBe(0);
  });

  it('returns length of non-empty string when other is empty', () => {
    const d1 = levenshteinDistance('', 'abc');
    const d2 = levenshteinDistance('abc', '');
    console.log(`[levenshtein] "" vs "abc" → ${d1}, "abc" vs "" → ${d2}`);
    expect(d1).toBe(3);
    expect(d2).toBe(3);
  });

  it('returns 1 for single substitution', () => {
    const d = levenshteinDistance('cat', 'car');
    console.log(`[levenshtein] "cat" vs "car" → distance: ${d} (substitution t→r)`);
    expect(d).toBe(1);
  });

  it('returns 1 for single insertion', () => {
    const d = levenshteinDistance('cat', 'cats');
    console.log(`[levenshtein] "cat" vs "cats" → distance: ${d} (insertion s)`);
    expect(d).toBe(1);
  });

  it('returns 1 for single deletion', () => {
    const d = levenshteinDistance('cats', 'cat');
    console.log(`[levenshtein] "cats" vs "cat" → distance: ${d} (deletion s)`);
    expect(d).toBe(1);
  });

  it('handles multi-edit distances', () => {
    const d = levenshteinDistance('kitten', 'sitting');
    console.log(`[levenshtein] "kitten" vs "sitting" → distance: ${d}`);
    expect(d).toBe(3);
  });
});

describe('detectTyposquatting', () => {
  const trusted = ['filesystem', 'web-search', 'calculator', 'weather'];

  it('detects typosquat with distance 1', () => {
    const result = detectTyposquatting('filesystam', trusted);
    console.log(`[typosquat] "filesystam" → match: ${result?.trustedName}, distance: ${result?.distance}`);
    expect(result).not.toBeNull();
    expect(result!.trustedName).toBe('filesystem');
    expect(result!.distance).toBe(1);
  });

  it('detects typosquat with distance 2', () => {
    const result = detectTyposquatting('calculater', trusted);
    console.log(`[typosquat] "calculater" → match: ${result?.trustedName}, distance: ${result?.distance}`);
    expect(result).not.toBeNull();
    expect(result!.trustedName).toBe('calculator');
  });

  it('returns null for exact match', () => {
    const result = detectTyposquatting('filesystem', trusted);
    console.log(`[typosquat] "filesystem" (exact) → result: ${result}`);
    expect(result).toBeNull();
  });

  it('returns null for distant names', () => {
    const result = detectTyposquatting('completely-different', trusted);
    console.log(`[typosquat] "completely-different" → result: ${result}`);
    expect(result).toBeNull();
  });

  it('normalizes hyphens and underscores', () => {
    const result = detectTyposquatting('web_search', trusted);
    console.log(`[typosquat] "web_search" (normalized) → result: ${result} (null = exact match after normalization)`);
    expect(result).toBeNull();
  });

  it('detects subtle typosquats', () => {
    const result = detectTyposquatting('weathr', trusted);
    console.log(`[typosquat] "weathr" → match: ${result?.trustedName}, distance: ${result?.distance}`);
    expect(result).not.toBeNull();
    expect(result!.trustedName).toBe('weather');
  });
});
