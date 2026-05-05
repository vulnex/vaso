import { describe, it, expect } from 'vitest';
import type { SSHTarget } from './ssh.js';
import type { MultiHostScanOptions } from './multi-host.js';
import { scanMultipleHosts, runConcurrent } from './multi-host.js';

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

describe('runConcurrent', () => {
  it('returns results in input order even when items finish out of order', async () => {
    const items = [40, 10, 30, 20];
    const out = await runConcurrent(items, 4, async (n) => {
      await new Promise(r => setTimeout(r, n));
      return n * 2;
    });
    expect(out).toEqual([80, 20, 60, 40]);
  });

  it('honors the concurrency limit', async () => {
    let inFlight = 0;
    let peak = 0;
    const items = Array.from({ length: 10 }, (_, i) => i);

    await runConcurrent(items, 3, async () => {
      inFlight++;
      peak = Math.max(peak, inFlight);
      await new Promise(r => setTimeout(r, 20));
      inFlight--;
      return 'ok';
    });

    expect(peak).toBeLessThanOrEqual(3);
    expect(peak).toBeGreaterThanOrEqual(2); // sanity: at least some parallelism
  });

  it('processes all items even when concurrency exceeds item count', async () => {
    const items = [1, 2, 3];
    const out = await runConcurrent(items, 100, async (n) => n * 10);
    expect(out).toEqual([10, 20, 30]);
  });

  it('handles empty input without spawning workers', async () => {
    const out = await runConcurrent([], 5, async () => 'never');
    expect(out).toEqual([]);
  });

  it('clamps concurrency below 1 to a single worker', async () => {
    let inFlight = 0;
    let peak = 0;
    await runConcurrent([1, 2, 3], 0, async () => {
      inFlight++;
      peak = Math.max(peak, inFlight);
      await new Promise(r => setTimeout(r, 5));
      inFlight--;
      return 'ok';
    });
    expect(peak).toBe(1);
  });
});
