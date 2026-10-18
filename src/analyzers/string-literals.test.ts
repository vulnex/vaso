import { describe, it, expect } from 'vitest';
import { lexJsLiterals, maskJsLiterals } from './string-literals.js';

const bodies = (code: string) => lexJsLiterals(code).map(([s, e]) => code.slice(s + 1, e - 1));

describe('lexJsLiterals', () => {
  it('skips quotes inside regex literals and comments', () => {
    expect(bodies(`var r=/[^A-Za-z0-9'()]+/g; // it's\nvar s="a'b"; /* don't */ var t='c';`)).toEqual(["a'b", 'c']);
  });

  it('reads a template literal over a line break and its substitutions as code', () => {
    expect(bodies('var t=`one\ntwo ${f("x")} three`;var u="v";')).toEqual(['one\ntwo ', 'x', ' three', 'v']);
  });

  it('a stray quote costs nothing: the literals after it on the line are read', () => {
    expect(bodies(`x.it's={chars:"table"};y="z"\nw='q'`)).toEqual(['table', 'z', 'q']);
  });

  it('division is not a regex', () => {
    expect(bodies('var a=b/2,c="d"/e;')).toEqual(['d']);
  });

  it('is linear on runs of unterminated quotes', () => {
    const start = Date.now();
    lexJsLiterals(`"${'\\"'.repeat(100_000)}\n` + `'`.repeat(100_000));
    expect(Date.now() - start).toBeLessThan(1000);
  });
});

describe('maskJsLiterals', () => {
  it('blanks the selected literals, keeping line breaks and columns', () => {
    const code = 'var a="keep",b=`drop\nme`;';
    const masked = maskJsLiterals(code, (v) => v.startsWith('drop'));
    expect(masked.length).toBe(code.length);
    expect(masked.split('\n')[0]).toContain('"keep"');
    expect(masked).not.toContain('drop');
  });
});
