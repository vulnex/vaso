import { describe, it, expect, beforeEach } from 'vitest';
import type { SSHTarget } from './ssh.js';
import type { MultiHostScanOptions } from './multi-host.js';
import { scanMultipleHosts } from './multi-host.js';

function makeTarget(host: string, user = 'root'): SSHTarget {
  return { user, host, port: 22 };
}

const defaultOptions: Omit<MultiHostScanOptions, 'targets'> = {
  transportOptions: {
    probeBinDir: '/usr/local/bin',
    manifest: {
      filePaths: [],
      globPatterns: [],
      commands: [],
      directoryListings: [],
      envPrefixes: [],
    },
    timeout: 30000,
  },
  scanOptions: {},
};

describe('scanMultipleHosts', () => {
  beforeEach(() => {
    // The current implementation always returns errors because SSH transport
    // is not yet implemented. We test the orchestration behavior.
  });

  it('returns error results for all hosts (transport not implemented)', async () => {
    const targets = [
      makeTarget('host1.example.com'),
      makeTarget('host2.example.com'),
      makeTarget('host3.example.com'),
    ];

    const results = await scanMultipleHosts({
      targets,
      ...defaultOptions,
    });

    expect(results).toHaveLength(3);
    // All should be errors since SSH transport is not yet implemented
    for (const r of results) {
      expect(r.error).toBeDefined();
      expect(r.result).toBeUndefined();
      expect(r.durationMs).toBeGreaterThanOrEqual(0);
    }
  });

  it('returns empty results for empty targets', async () => {
    const results = await scanMultipleHosts({
      targets: [],
      ...defaultOptions,
    });

    expect(results).toEqual([]);
  });

  it('preserves target information in results', async () => {
    const targets = [
      makeTarget('alpha.host', 'deploy'),
      makeTarget('beta.host', 'admin'),
    ];

    const results = await scanMultipleHosts({
      targets,
      ...defaultOptions,
    });

    expect(results).toHaveLength(2);
    expect(results[0].target.host).toBe('alpha.host');
    expect(results[0].target.user).toBe('deploy');
    expect(results[1].target.host).toBe('beta.host');
    expect(results[1].target.user).toBe('admin');
  });

  it('error message suggests using snapshot workflow', async () => {
    const results = await scanMultipleHosts({
      targets: [makeTarget('any.host')],
      ...defaultOptions,
    });

    expect(results[0].error).toContain('not yet implemented');
    expect(results[0].error).toContain('--snapshot');
  });

  it('tracks duration for each host', async () => {
    const results = await scanMultipleHosts({
      targets: [makeTarget('host1'), makeTarget('host2')],
      ...defaultOptions,
    });

    for (const r of results) {
      expect(typeof r.durationMs).toBe('number');
      expect(r.durationMs).toBeGreaterThanOrEqual(0);
    }
  });
});
