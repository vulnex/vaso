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
      { startLine: 1, code: '// === dist/a.js ===\nconst a = 1;\n' },
      { startLine: 4, code: '// === dist/b.js ===\nconst a = 2;' },
    ]);
  });

  it('returns single-file source as one chunk', () => {
    expect(sourceChunks('const a = 1;')).toEqual([{ startLine: 1, code: 'const a = 1;' }]);
  });
});
