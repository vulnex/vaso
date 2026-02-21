import { describe, it, expect } from 'vitest';
import { getNestedValue, setNestedValue, deepMerge } from './utils.js';

describe('getNestedValue', () => {
  it('retrieves a nested value by dot path', () => {
    expect(getNestedValue({ a: { b: 1 } }, 'a.b')).toBe(1);
  });

  it('returns undefined for missing paths', () => {
    expect(getNestedValue({ a: 1 }, 'b.c')).toBeUndefined();
  });
});

describe('setNestedValue', () => {
  it('sets a deeply nested value', () => {
    const obj: Record<string, unknown> = {};
    setNestedValue(obj, 'a.b.c', 1);
    expect(obj).toEqual({ a: { b: { c: 1 } } });
  });
});

describe('deepMerge', () => {
  it('merges shallow properties', () => {
    const result = deepMerge({ a: 1, b: 2 }, { b: 3, c: 4 });
    expect(result).toEqual({ a: 1, b: 3, c: 4 });
  });

  it('merges deeply nested objects', () => {
    const base = { gateway: { host: '127.0.0.1', port: 8080, tls: false } };
    const override = { gateway: { tls: true, auth: 'token' } };
    const result = deepMerge(base, override);
    expect(result).toEqual({
      gateway: { host: '127.0.0.1', port: 8080, tls: true, auth: 'token' },
    });
  });

  it('override wins on conflict', () => {
    const result = deepMerge(
      { sandbox: true, permissions: { read: true } },
      { sandbox: false, permissions: { read: false, write: true } },
    );
    expect(result).toEqual({
      sandbox: false,
      permissions: { read: false, write: true },
    });
  });

  it('arrays from override replace base arrays', () => {
    const result = deepMerge(
      { tools: ['a', 'b'], nested: { list: [1, 2] } },
      { tools: ['c'], nested: { list: [3, 4, 5] } },
    );
    expect(result).toEqual({
      tools: ['c'],
      nested: { list: [3, 4, 5] },
    });
  });

  it('does not mutate base or override', () => {
    const base = { a: { b: 1 } };
    const override = { a: { c: 2 } };
    const baseCopy = JSON.parse(JSON.stringify(base));
    const overrideCopy = JSON.parse(JSON.stringify(override));
    deepMerge(base, override);
    expect(base).toEqual(baseCopy);
    expect(override).toEqual(overrideCopy);
  });

  it('handles empty objects', () => {
    expect(deepMerge({}, { a: 1 })).toEqual({ a: 1 });
    expect(deepMerge({ a: 1 }, {})).toEqual({ a: 1 });
    expect(deepMerge({}, {})).toEqual({});
  });
});
