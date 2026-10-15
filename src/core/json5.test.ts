import { describe, it, expect } from 'vitest';
import { parseJson5 } from './json5.js';
import { parseJsonLenient } from './jsonc.js';

describe('parseJson5', () => {
  it('parses the JSON5 features OpenClaw configs use', () => {
    const text = `{
      // comment
      gateway: { bind: 'lan', port: 0x4965, tls: { enabled: false, }, },
      /* block */ "quoted": "a\\
b", neg: -.5, plus: +1, big: 1e3, inf: -Infinity, list: [1, 2,],
    }`;
    expect(parseJson5(text)).toEqual({
      gateway: { bind: 'lan', port: 0x4965, tls: { enabled: false } },
      quoted: 'ab', neg: -0.5, plus: 1, big: 1000, inf: -Infinity, list: [1, 2],
    });
  });

  it('keeps __proto__ as data and rejects garbage', () => {
    const v = parseJson5('{__proto__: {polluted: true}}') as Record<string, unknown>;
    expect(Object.getPrototypeOf(v)).toBe(Object.prototype);
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
    expect(() => parseJson5('{a: }')).toThrow(SyntaxError);
    expect(() => parseJson5('{a: 1} x')).toThrow(/trailing/);
  });

  it('parseJsonLenient falls back JSON → JSONC → JSON5 and reports the JSON error', () => {
    expect(parseJsonLenient('{"a":1}')).toEqual({ a: 1 });
    expect(parseJsonLenient('{"a":1, // c\n}')).toEqual({ a: 1 });
    expect(parseJsonLenient("{a: 'x'}")).toEqual({ a: 'x' });
    expect(() => parseJsonLenient('{a: ')).toThrow(/JSON/);
  });
});

describe('line comments in CR-only files', () => {
  it('end a // comment at CR (and U+2028) instead of swallowing the rest of the file', () => {
    expect(parseJson5('{ // note\r  gateway: { bind: "lan" },\r}')).toEqual({ gateway: { bind: 'lan' } });
    expect(parseJson5('{ // note  a: 1 }')).toEqual({ a: 1 });
    expect(parseJsonLenient('{ // note\r  "a": 1\r}')).toEqual({ a: 1 });
  });
});
