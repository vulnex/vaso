import { describe, it, expect } from 'vitest';
import { parseSSHTarget } from './ssh.js';

describe('parseSSHTarget', () => {
  it('parses user@host with default port 22', () => {
    expect(parseSSHTarget('user@host')).toEqual({
      user: 'user',
      host: 'host',
      port: 22,
    });
  });

  it('parses user@host:port', () => {
    expect(parseSSHTarget('user@host:2222')).toEqual({
      user: 'user',
      host: 'host',
      port: 2222,
    });
  });

  it('parses user@ip-address', () => {
    expect(parseSSHTarget('deploy@10.0.0.1')).toEqual({
      user: 'deploy',
      host: '10.0.0.1',
      port: 22,
    });
  });

  it('parses user@ip-address:port', () => {
    expect(parseSSHTarget('deploy@10.0.0.1:22')).toEqual({
      user: 'deploy',
      host: '10.0.0.1',
      port: 22,
    });
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
