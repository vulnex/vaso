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
});
