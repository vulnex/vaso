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

  it('a fragment starting inside a template literal: its tail is a literal (a bundle line cut out, dt17)', () => {
    // @googlemaps/code-assist-mcp 0.2.1 dist/index.js line 46 alone: cp864's template continues from line 45
    expect(bodies('import x from "y";\n\\v\\f !"#$&\'()[\\\\]^_\\`abc`},ibm864:"cp864"')).toEqual(['y', '\\v\\f !"#$&\'()[\\\\]^_\\`abc', 'cp864']);
    // an ordinary file is lexed from the start
    expect(bodies('var a = `t`; var b = "c";')).toEqual(['t', 'c']);
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
