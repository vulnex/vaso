import { describe, it, expect } from 'vitest';
import { parseYamlSafe } from './yaml-safe.js';

describe('parseYamlSafe', () => {
  it('parses ordinary YAML, including shared (acyclic) aliases', () => {
    expect(parseYamlSafe('a: &x {k: 1}\nb: *x\n')).toEqual({ a: { k: 1 }, b: { k: 1 } });
  });

  it('rejects a self-referencing alias instead of returning a circular object', () => {
    expect(() => parseYamlSafe('a: &x\n  self: *x\n')).toThrow(/self-referencing alias/);
  });
});
