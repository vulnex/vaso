import { describe, it, expect } from 'vitest';
import { parseRemoteOptions } from './remote-options.js';

describe('parseRemoteOptions', () => {
  it('applies defaults and rejects malformed or zero values', () => {
    expect(parseRemoteOptions({})).toEqual({ concurrency: 5, retries: 0, sshTimeoutSec: 60 });
    expect(parseRemoteOptions({ parallel: '2', sshRetries: '1', sshTimeout: '9' })).toEqual({ concurrency: 2, retries: 1, sshTimeoutSec: 9 });
    expect(() => parseRemoteOptions({ parallel: '0' })).toThrow(/at least 1/);
    expect(() => parseRemoteOptions({ sshTimeout: 'abc' })).toThrow(/--ssh-timeout/);
    expect(() => parseRemoteOptions({ sshRetries: '1.5' })).toThrow(/--ssh-retries/);
  });

  it('rejects an --ssh-timeout that would overflow Node timers (and fire after 1 ms)', () => {
    expect(parseRemoteOptions({ sshTimeout: '86400' }).sshTimeoutSec).toBe(86400);
    expect(() => parseRemoteOptions({ sshTimeout: '86401' })).toThrow(/at most 86400/);
    expect(() => parseRemoteOptions({ sshTimeout: '9999999999' })).toThrow(/at most/);
  });

  it('bounds --ssh-retries', () => {
    expect(parseRemoteOptions({ sshRetries: '10' }).retries).toBe(10);
    expect(() => parseRemoteOptions({ sshRetries: '11' })).toThrow(/at most 10/);
  });

  it('rejects option combinations that can\'t apply', () => {
    const host = ['root@h'];
    expect(() => parseRemoteOptions({ snapshot: 's.json', host })).toThrow(/mutually exclusive/);
    expect(() => parseRemoteOptions({ snapshot: 's.json', inventory: 'i.yaml' })).toThrow(/mutually exclusive/);
    expect(() => parseRemoteOptions({ saveSnapshot: 'd' })).toThrow(/--save-snapshot applies to remote scans only/);
    expect(() => parseRemoteOptions({ sshKey: '~/.ssh/id' })).toThrow(/--ssh-key applies to remote scans only/);
    expect(() => parseRemoteOptions({ sudo: true, snapshot: 's.json' })).toThrow(/--sudo applies to remote scans only/);
    expect(() => parseRemoteOptions({ sshKey: '', host })).toThrow(/needs a key file/);
    expect(parseRemoteOptions({ sshKey: 'k', sudo: true, saveSnapshot: 'd', host }).retries).toBe(0);
  });
});
