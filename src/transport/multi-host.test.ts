import { describe, it, expect } from 'vitest';
import type { SSHTarget } from './ssh.js';
import type { MultiHostScanOptions } from './multi-host.js';
import { scanMultipleHosts } from './multi-host.js';

function makeTarget(host: string, user = 'root'): SSHTarget {
  return { user, host, port: 22 };
}

const defaultOptions: Omit<MultiHostScanOptions, 'targets'> = {
  transportOptions: {
    probeBinDir: '/nonexistent/probe/dist',
    manifest: {
      filePaths: [],
      globPatterns: [],
      commands: [],
      directoryListings: [],
      envPrefixes: [],
    },
    timeout: 5000,
  },
  scanOptions: {},
};

describe('scanMultipleHosts', () => {
  it('returns empty results for empty targets', async () => {
    const results = await scanMultipleHosts({
      targets: [],
      ...defaultOptions,
    });

    expect(results).toEqual([]);
  });

  it('returns error results when SSH connection fails', async () => {
    const targets = [
      makeTarget('192.0.2.1', 'testuser'), // RFC 5737 TEST-NET — guaranteed unreachable
    ];

    const results = await scanMultipleHosts({
      targets,
      ...defaultOptions,
    });

    expect(results).toHaveLength(1);
    expect(results[0].error).toBeDefined();
    expect(results[0].result).toBeUndefined();
    expect(results[0].target.host).toBe('192.0.2.1');
    expect(results[0].durationMs).toBeGreaterThanOrEqual(0);
  }, 30000);

  it('preserves target information in error results', async () => {
    const targets = [
      { ...makeTarget('192.0.2.2', 'deploy'), label: 'test-box' },
    ];

    const results = await scanMultipleHosts({
      targets,
      ...defaultOptions,
    });

    expect(results).toHaveLength(1);
    expect(results[0].target.host).toBe('192.0.2.2');
    expect(results[0].target.user).toBe('deploy');
    expect(results[0].target.label).toBe('test-box');
  }, 30000);

  it('tracks duration for each host', async () => {
    const results = await scanMultipleHosts({
      targets: [makeTarget('192.0.2.3')],
      ...defaultOptions,
    });

    expect(results[0].durationMs).toBeGreaterThanOrEqual(0);
    expect(typeof results[0].durationMs).toBe('number');
  }, 30000);
});
