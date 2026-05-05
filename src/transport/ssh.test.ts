import { describe, it, expect, vi } from 'vitest';
import { parseSSHTarget, withRetry } from './ssh.js';

describe('parseSSHTarget', () => {
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

  it('ignores port 0 (out of valid range)', () => {
    const result = parseSSHTarget('user@host:0');
    expect(result.host).toBe('host:0');
    expect(result.port).toBe(22);
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
