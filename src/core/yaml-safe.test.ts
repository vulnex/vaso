import { describe, it, expect } from 'vitest';
import { parseYamlSafe } from './yaml-safe.js';

describe('parseYamlSafe', () => {
  it('parses ordinary YAML, including shared (acyclic) aliases', () => {
    expect(parseYamlSafe('a: &x {k: 1}\nb: *x\n')).toEqual({ a: { k: 1 }, b: { k: 1 } });
  });

  it('rejects a self-referencing alias instead of returning a circular object', () => {
    expect(() => parseYamlSafe('a: &x\n  self: *x\n')).toThrow(/self-referencing alias/);
  });

  it('resolves merge keys, explicit keys winning over merged ones', () => {
    expect(parseYamlSafe('d: &u {mode: off, cron_mode: approve}\napprovals:\n  <<: *u\n  mode: manual\n'))
      .toEqual({ d: { mode: 'off', cron_mode: 'approve' }, approvals: { mode: 'manual', cron_mode: 'approve' } });
    expect(parseYamlSafe('a: &a {k: 1}\nb: &b {j: 2}\nc: {<<: [*a, *b], k: 9}\n')).toMatchObject({ c: { k: 9, j: 2 } });
    // Not a merge source: kept as a plain key
    expect(parseYamlSafe('a: {<<: text}\n')).toEqual({ a: { '<<': 'text' } });
  });

  it('rejects a merge key that merges its own anchor', () => {
    expect(() => parseYamlSafe('a: &x\n  <<: *x\n')).toThrow();
    expect(() => parseYamlSafe('a: &x\n  b: {<<: *x}\n')).toThrow();
  });

  it('resolves a duplicate key to its last value, as PyYAML does (dt15 P6)', () => {
    expect(parseYamlSafe('approvals:\n  mode: manual\nterminal: {x: 1}\napprovals:\n  mode: off\n'))
      .toEqual({ approvals: { mode: 'off' }, terminal: { x: 1 } });
    expect(parseYamlSafe('a: {k: 1, k: 2}\n')).toEqual({ a: { k: 2 } });
  });

  it('rejects a duplicate key on request, naming it and its line', () => {
    const dup = 'approvals:\n  mode: manual\napprovals:\n  mode: off\n';
    expect(() => parseYamlSafe(dup, { duplicateKeys: 'reject' })).toThrow('found duplicate key "approvals" at line 3');
    expect(() => parseYamlSafe('a:\n  k: 1\n  k: 2\n', { duplicateKeys: 'reject' })).toThrow('"k" at line 3');
    // Equal keys in different mappings, merge keys and 1 vs "1" are not duplicates
    const fine = 'x: {k: 1}\ny: {k: 2}\nd: &d {a: 1}\ne:\n  <<: *d\n  <<: *d\nn: {1: a, "1": b}\n';
    expect(parseYamlSafe(fine, { duplicateKeys: 'reject' })).toMatchObject({ x: { k: 1 }, y: { k: 2 }, e: { a: 1 } });
    const many = Array.from({ length: 40_000 }, (_, i) => `k${i}: v`).join('\n');
    const start = Date.now();
    parseYamlSafe(many, { duplicateKeys: 'reject' });
    expect(Date.now() - start).toBeLessThan(4000);
  });

  it('parses many keys in linear time', () => {
    const many = Array.from({ length: 40_000 }, (_, i) => `k${i}: v`).join('\n');
    const start = Date.now();
    const value = parseYamlSafe(many) as Record<string, string>;
    expect(Date.now() - start).toBeLessThan(2000);
    expect(Object.keys(value)).toHaveLength(40_000);
    expect(value.k39999).toBe('v');
  });

  it('still rejects malformed YAML', () => {
    expect(() => parseYamlSafe('a: [1, 2\nb: c')).toThrow();
  });
});
