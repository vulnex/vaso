import { describe, it, expect, vi } from 'vitest';
import { describeConnectFailure, parseProbeOutput, parseSSHTarget, uniqueTargets, withRetry } from './ssh.js';

describe('parseProbeOutput', () => {
  const target = { user: 'u', host: 'h.test' };
  const valid = { version: 1, platform: 'linux', hostname: 'h', homedir: '/home/u', files: {}, directories: {}, commandOutputs: {} };

  it('accepts what a probe prints', () => {
    expect(parseProbeOutput(JSON.stringify(valid), target).hostname).toBe('h');
  });

  it('holds remote output to the snapshot-file checks, as one escaped line', () => {
    expect(() => parseProbeOutput('null', target)).toThrow(/u@h\.test returned unusable probe output, host not scanned — Invalid probe output: Snapshot is not a JSON object/);
    expect(() => parseProbeOutput('{"a":', target)).toThrow(/not valid JSON/);
    const big = 'a'.repeat(48 * 1024 * 1024 + 1);
    expect(() => parseProbeOutput(JSON.stringify({ ...valid, files: { '/x': { content: big, mode: 0o644, exists: true } } }), target)).toThrow(/per-file limit/);
    let message = '';
    try {
      parseProbeOutput(JSON.stringify({ ...valid, files: { '/a\n\u001b]0;pwned\u0007': { content: big, mode: 0o644, exists: true } } }), target);
    } catch (err) { message = (err as Error).message; }
    expect(message).not.toMatch(/[\n\u001b\u0007]/);
    expect(message).toContain('\\x1b');
  });
});

describe('parseSSHTarget', () => {
  it('rejects an empty user, option-like parts and control characters', () => {
    expect(() => parseSSHTarget('@192.0.2.1')).toThrow(/missing user/);
    expect(() => parseSSHTarget('-oProxyCommand=x@192.0.2.1')).toThrow(/may not start with "-"/);
    expect(() => parseSSHTarget('u@-oProxyCommand=x')).toThrow(/may not start with "-"/);
    expect(() => parseSSHTarget('u ser@host')).toThrow(/whitespace/);
    expect(() => parseSSHTarget('u@192.0.2.1:99999')).toThrow(/port must be/);
    expect(() => parseSSHTarget('u@192.0.2.1:0')).toThrow(/port must be/);
  });

  it('dedupes repeated targets', () => {
    const { targets, duplicates } = uniqueTargets([parseSSHTarget('u@h'), parseSSHTarget('u@h:22'), parseSSHTarget('u@h:2222')]);
    expect(targets.map(t => t.port)).toEqual([22, 2222]);
    expect(duplicates).toEqual(['u@h']);
  });

  it('parses user@host with default port 22', () => {
    expect(parseSSHTarget('user@host')).toEqual({
      user: 'user',
      host: 'host',
      port: 22,
      label: 'user@host',
    });
  });

  it('parses user@host:port', () => {
    expect(parseSSHTarget('user@host:2222')).toEqual({
      user: 'user',
      host: 'host',
      port: 2222,
      label: 'user@host:2222',
    });
  });

  it('parses user@ip-address', () => {
    expect(parseSSHTarget('deploy@10.0.0.1')).toEqual({
      user: 'deploy',
      host: '10.0.0.1',
      port: 22,
      label: 'deploy@10.0.0.1',
    });
  });

  it('parses user@ip-address:port', () => {
    expect(parseSSHTarget('deploy@10.0.0.1:22')).toEqual({
      user: 'deploy',
      host: '10.0.0.1',
      port: 22,
      label: 'deploy@10.0.0.1',
    });
  });

  it('omits port from default label when port is 22', () => {
    const t = parseSSHTarget('admin@example.com');
    expect(t.label).toBe('admin@example.com');
  });

  it('includes non-default port in default label', () => {
    const t = parseSSHTarget('admin@example.com:2200');
    expect(t.label).toBe('admin@example.com:2200');
  });

  it('throws when @ is missing', () => {
    expect(() => parseSSHTarget('host')).toThrow('expected user@host[:port]');
  });

  it('throws when @ is missing even with port', () => {
    expect(() => parseSSHTarget('host:2222')).toThrow('expected user@host[:port]');
  });

  it('throws when hostname is empty', () => {
    expect(() => parseSSHTarget('user@')).toThrow('missing hostname');
  });

  it('ignores invalid port and treats it as part of host', () => {
    const result = parseSSHTarget('user@host:notaport');
    expect(result.host).toBe('host:notaport');
    expect(result.port).toBe(22);
  });

  it('reads IPv6 hosts: bare (no port) and bracketed with a port', () => {
    expect(parseSSHTarget('u@::1')).toMatchObject({ host: '::1', port: 22, label: 'u@::1' });
    expect(parseSSHTarget('u@fe80::1')).toMatchObject({ host: 'fe80::1', port: 22 });
    expect(parseSSHTarget('u@[::1]:1')).toMatchObject({ host: '::1', port: 1, label: 'u@[::1]:1' });
    expect(parseSSHTarget('u@[2001:db8::5]')).toMatchObject({ host: '2001:db8::5', port: 22 });
    expect(() => parseSSHTarget('u@[::1')).toThrow(/ipv6/);
    expect(() => parseSSHTarget('u@[::1]x')).toThrow(/ipv6/);
    expect(() => parseSSHTarget('u@[::1]:0')).toThrow(/port must be/);
  });

  it('rejects port 0 instead of reading "host:0" as a host name', () => {
    expect(() => parseSSHTarget('user@host:0')).toThrow(/port must be/);
  });

  it('uses last colon for port when multiple colons present', () => {
    // IPv6-like or unusual hostname
    const result = parseSSHTarget('user@host:2222');
    expect(result.port).toBe(2222);
    expect(result.host).toBe('host');
  });
});

describe('withRetry', () => {
  const noSleep = async () => {};

  it('returns the value when fn succeeds on first try', async () => {
    const fn = vi.fn().mockResolvedValue('ok');
    const out = await withRetry({ retries: 3, fn, sleep: noSleep });
    expect(out).toBe('ok');
    expect(fn).toHaveBeenCalledTimes(1);
  });

  it('retries on failure and returns the eventual success', async () => {
    const fn = vi.fn()
      .mockRejectedValueOnce(new Error('boom-1'))
      .mockRejectedValueOnce(new Error('boom-2'))
      .mockResolvedValueOnce('ok');
    const onRetry = vi.fn();

    const out = await withRetry({ retries: 3, fn, onRetry, sleep: noSleep });

    expect(out).toBe('ok');
    expect(fn).toHaveBeenCalledTimes(3);
    expect(onRetry).toHaveBeenCalledTimes(2);
    expect(onRetry).toHaveBeenNthCalledWith(1, 1, expect.objectContaining({ message: 'boom-1' }));
    expect(onRetry).toHaveBeenNthCalledWith(2, 2, expect.objectContaining({ message: 'boom-2' }));
  });

  it('throws the final error after exhausting retries', async () => {
    const fn = vi.fn()
      .mockRejectedValueOnce(new Error('one'))
      .mockRejectedValueOnce(new Error('two'))
      .mockRejectedValueOnce(new Error('three'));

    await expect(withRetry({ retries: 2, fn, sleep: noSleep }))
      .rejects.toThrow('three');
    expect(fn).toHaveBeenCalledTimes(3); // initial + 2 retries
  });

  it('does not retry when retries is 0', async () => {
    const fn = vi.fn().mockRejectedValue(new Error('first-and-only'));
    await expect(withRetry({ retries: 0, fn, sleep: noSleep }))
      .rejects.toThrow('first-and-only');
    expect(fn).toHaveBeenCalledTimes(1);
  });

  it('calls sleep before each retry, with the attempt number', async () => {
    const fn = vi.fn()
      .mockRejectedValueOnce(new Error('a'))
      .mockRejectedValueOnce(new Error('b'))
      .mockResolvedValueOnce('ok');
    const sleep = vi.fn().mockResolvedValue(undefined);

    await withRetry({ retries: 2, fn, sleep });

    expect(sleep).toHaveBeenCalledTimes(2);
    expect(sleep).toHaveBeenNthCalledWith(1, 1);
    expect(sleep).toHaveBeenNthCalledWith(2, 2);
  });
});

describe('describeConnectFailure', () => {
  const t = { user: 'u', host: 'h' };
  it('reports a spawn timeout (no exit code) as a timeout with the configured seconds', () => {
    expect(describeConnectFailure(t, null, 'SIGTERM', 3000)).toMatch(/u@h timed out after 3s/);
  });
  it('explains ssh exit 255', () => {
    expect(describeConnectFailure(t, 255, null, 60000)).toMatch(/ssh exit 255: connection refused, unknown host, or authentication rejected/);
  });
  it("reports ssh exit 255 after the connect timeout as a timeout (ssh's ConnectTimeout won the race)", () => {
    expect(describeConnectFailure(t, 255, null, 5000, 5004)).toMatch(/u@h timed out after 5s/);
    // Seen with a busy event loop: the exit is handled late, still a timeout.
    expect(describeConnectFailure(t, 255, null, 5000, 22889)).toMatch(/timed out after 5s/);
    // A fast 255 (refused, unknown host, rejected key) keeps its explanation.
    expect(describeConnectFailure(t, 255, null, 5000, 120)).toMatch(/connection refused, unknown host/);
  });
  it('names other signals and exit codes', () => {
    expect(describeConnectFailure(t, null, 'SIGKILL', 60000)).toMatch(/terminated by SIGKILL/);
    expect(describeConnectFailure(t, 1, null, 60000)).toMatch(/failed \(ssh exit 1\)/);
  });
});
