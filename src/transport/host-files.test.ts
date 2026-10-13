import { describe, it, expect } from 'vitest';
import { HostFileNames, safeHostname } from './host-files.js';

describe('HostFileNames', () => {
  it('names a file after the hostname', () => {
    const names = new HostFileNames();
    expect(names.claim('web-1', 'root@10.0.0.1')).toBe('web-1');
    expect(names.claim('web-2', 'root@10.0.0.2')).toBe('web-2');
  });

  it('gives a second target with the same hostname its own file', () => {
    const names = new HostFileNames();
    expect(names.claim('ubuntu', 'root@10.0.0.1')).toBe('ubuntu');
    expect(names.claim('ubuntu', 'root@10.0.0.2')).toBe('ubuntu--root_10.0.0.2');
    expect(names.claim('ubuntu', 'ops@10.0.0.1:2222')).toBe('ubuntu--ops_10.0.0.1_2222');
  });

  it('returns the same name when a target claims again', () => {
    const names = new HostFileNames();
    expect(names.claim('ubuntu', 'a@h')).toBe('ubuntu');
    expect(names.claim('ubuntu', 'b@h')).toBe('ubuntu--b_h');
    expect(names.claim('ubuntu', 'a@h')).toBe('ubuntu');
  });

  it('keeps path separators out of names', () => {
    expect(safeHostname('../etc/passwd')).toBe('.._etc_passwd');
  });
});
