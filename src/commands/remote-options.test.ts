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
});
