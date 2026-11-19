import { describe, it, expect } from 'vitest';
import { sourceSegments, withoutStringText, nearbyText } from './source-segments.js';
import { sourceChunks } from '../analyzers/js-parse.js';

describe('sourceSegments', () => {
  it('keeps ordinary lines whole and drops comment lines', () => {
    const segs = sourceSegments('const a = 1;\n// note: token=1\n  * doc\nconst b = 2;');
    expect(segs).toEqual([{ line: 1, text: 'const a = 1;' }, { line: 4, text: 'const b = 2;' }]);
  });

  it('splits a minified line into statements on the same line number', () => {
    const minified = `${'x'.repeat(380)};let token=t;fetch(u);a.b=c`;
    const segs = sourceSegments(`ok\n${minified}`);
    expect(segs.map((s) => s.line)).toEqual([1, 2, 2, 2, 2]);
    expect(segs.map((s) => s.text.trim())).toContain('let token=t;');
  });

  it('drops Python docstring bodies but keeps assigned multi-line strings and the code after them', () => {
    const code = ['def f():', '    """Doc', '    /authorize', '    """', '    x = 1', 'T = """', 'data', '"""', 'y = 2'].join('\n');
    expect(sourceSegments(code, { python: true }).map((s) => s.line)).toEqual([1, 5, 6, 7, 8, 9]);
    // JavaScript sources are unchanged
    expect(sourceSegments(code).map((s) => s.line)).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9]);
  });

  it('bounds a long statement without `;`, cutting outside strings where it can (dt15)', async () => {
    const { MAX_SEGMENT } = await import('./source-segments.js');
    const obj = `x={${Array.from({ length: 2000 }, (_, i) => `k${i}:"v${i}"`).join(',')}}`;
    const segs = sourceSegments(obj);
    expect(segs.length).toBeGreaterThan(1);
    expect(segs.every((s) => s.text.length <= MAX_SEGMENT && s.line === 1)).toBe(true);
    expect(segs.map((s) => s.text).join('')).toBe(obj); // cut at commas: nothing added
    expect(segs.every((s) => !withoutStringText(s.text).includes('v1'))).toBe(true);
  });

  it('closes and reopens a string longer than a segment, so it stays a string', async () => {
    const { MAX_SEGMENT } = await import('./source-segments.js');
    const blob = `const img="data:image/png,${'QUJD\\"'.repeat(1500)}";`;
    const segs = sourceSegments(`a();${'b'.repeat(400)}\n${blob}`);
    const pieces = segs.filter((s) => s.line === 2);
    expect(pieces.length).toBeGreaterThan(2);
    for (const s of pieces) {
      expect(s.text.length).toBeLessThanOrEqual(MAX_SEGMENT);
      expect(withoutStringText(s.text)).not.toMatch(/QUJD/);
    }
    const start = Date.now();
    sourceSegments(`${'a '.repeat(500_000)}\n${'"'.repeat(1)}${'x'.repeat(1_000_000)}`);
    expect(Date.now() - start).toBeLessThan(1000);
  });

  it('gives nearby text across neighbouring segments', () => {
    const segs = sourceSegments('a\nb\nc\nd');
    expect(nearbyText(segs, 1, 1)).toBe('a\nb\nc');
  });
});

describe('withoutStringText', () => {
  it.each([
    ['console.log("refreshed access token")', 'console.log("")'],
    ['log(`removed token for ${user.email}.`)', 'log(`${user.email}`)'],
    ["x = 'it\\'s'; y = token", "x = ''; y = token"],
    ['a(`o ${b(`i ${token} t`)} tail`)', 'a(`${b(`${token}`)}`)'],
  ])('%s', (input, expected) => {
    expect(withoutStringText(input)).toBe(expected);
  });
});

describe('sourceChunks', () => {
  it('splits --resolve-packages concatenations at file headers', () => {
    const code = '// === dist/a.js ===\nconst a = 1;\n\n// === dist/b.js ===\nconst a = 2;';
    expect(sourceChunks(code)).toEqual([
      { startLine: 1, code: '// === dist/a.js ===\nconst a = 1;\n', path: 'dist/a.js' },
      { startLine: 4, code: '// === dist/b.js ===\nconst a = 2;', path: 'dist/b.js' },
    ]);
  });

  it('returns single-file source as one chunk', () => {
    expect(sourceChunks('const a = 1;')).toEqual([{ startLine: 1, code: 'const a = 1;' }]);
  });
});
