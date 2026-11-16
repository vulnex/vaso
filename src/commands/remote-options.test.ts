import { describe, it, expect } from 'vitest';
import { parseRemoteOptions, unusedTuningOptions } from './remote-options.js';

describe('parseRemoteOptions', () => {
  const host = ['h'];
  it('applies defaults and rejects malformed or zero values', () => {
    expect(parseRemoteOptions({})).toEqual({ concurrency: 5, retries: 0, sshTimeoutSec: 60 });
    expect(parseRemoteOptions({ parallel: '2', sshRetries: '1', sshTimeout: '9', host })).toEqual({ concurrency: 2, retries: 1, sshTimeoutSec: 9 });
    expect(() => parseRemoteOptions({ parallel: '0', host })).toThrow(/at least 1/);
    expect(() => parseRemoteOptions({ sshTimeout: 'abc', host })).toThrow(/--ssh-timeout/);
    expect(() => parseRemoteOptions({ sshRetries: '1.5', host })).toThrow(/--ssh-retries/);
  });

  it('rejects an --ssh-timeout that would overflow Node timers (and fire after 1 ms)', () => {
    expect(parseRemoteOptions({ sshTimeout: '86400', host }).sshTimeoutSec).toBe(86400);
    expect(() => parseRemoteOptions({ sshTimeout: '86401', host })).toThrow(/at most 86400/);
    expect(() => parseRemoteOptions({ sshTimeout: '9999999999', host })).toThrow(/at most/);
  });

  it('bounds --ssh-retries', () => {
    expect(parseRemoteOptions({ sshRetries: '10', host }).retries).toBe(10);
    expect(() => parseRemoteOptions({ sshRetries: '11', host })).toThrow(/at most 10/);
  });

  it('rejects option combinations that can\'t apply', () => {
    expect(() => parseRemoteOptions({ snapshot: 's.json', host })).toThrow(/mutually exclusive/);
    expect(() => parseRemoteOptions({ snapshot: 's.json', inventory: 'i.yaml' })).toThrow(/mutually exclusive/);
    expect(() => parseRemoteOptions({ saveSnapshot: 'd' })).toThrow(/--save-snapshot applies to remote scans only/);
    expect(() => parseRemoteOptions({ sshKey: '', host })).toThrow(/needs a key file/);
    expect(parseRemoteOptions({ sshKey: 'k', sudo: true, saveSnapshot: 'd', host }).retries).toBe(0);
  });

  it('accepts (and ignores) --ssh-timeout, --ssh-retries and --parallel on local and snapshot scans, as 1.4.1 did', () => {
    expect(parseRemoteOptions({ sshTimeout: '30' }).sshTimeoutSec).toBe(30);
    expect(parseRemoteOptions({ parallel: '2', sshRetries: '1', snapshot: 's.json' })).toEqual({ concurrency: 2, retries: 1, sshTimeoutSec: 60 });
    expect(unusedTuningOptions({ parallel: '2', sshTimeout: '30' })).toEqual(['--ssh-timeout', '--parallel']);
    expect(unusedTuningOptions({ parallel: '2', host })).toEqual([]);
    // still validated: a typo is a usage error wherever it appears
    expect(() => parseRemoteOptions({ sshTimeout: 'abc' })).toThrow(/--ssh-timeout/);
  });

  it('accepts (and ignores) --ssh-key and --sudo on local and snapshot scans, as 1.4.1 did', () => {
    expect(parseRemoteOptions({ sshKey: '~/.ssh/id' })).toEqual({ concurrency: 5, retries: 0, sshTimeoutSec: 60 });
    expect(parseRemoteOptions({ sudo: true, snapshot: 's.json' }).retries).toBe(0);
    expect(unusedTuningOptions({ sshKey: 'k', sudo: true, sshTimeout: '30' })).toEqual(['--ssh-key', '--sudo', '--ssh-timeout']);
    expect(unusedTuningOptions({ sshKey: 'k', sudo: true, inventory: 'i.yaml' })).toEqual([]);
    expect(unusedTuningOptions({ sudo: false })).toEqual([]);
    // still validated
    expect(() => parseRemoteOptions({ sshKey: '' })).toThrow(/needs a key file/);
    expect(() => parseRemoteOptions({ sshKey: '  ', snapshot: 's.json' })).toThrow(/needs a key file/);
  });
});
