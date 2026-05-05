/**
 * Multi-host scanning orchestrator.
 *
 * Connects to each SSH target, uploads the probe binary,
 * collects a snapshot, and runs the scan engine against it.
 */

import type { SSHTarget } from './ssh.js';
import type { ProbeManifest, ProbeSnapshot } from '../core/snapshot-types.js';
import type { ScanResult } from '../core/types.js';

export interface TransportOptions {
  probeBinDir: string;
  manifest: ProbeManifest;
  timeout: number;
}

export interface MultiHostScanOptions {
  targets: SSHTarget[];
  transportOptions: TransportOptions;
  scanOptions: {
    agentFilter?: string;
    format?: string;
  };
  /** Max hosts to scan concurrently. Default: 5. */
  concurrency?: number;
  /** Additional SSH attempts after the first failure. Default: 0. */
  retries?: number;
  /** Invoked per host once a snapshot is collected, before scanning. */
  onSnapshot?: (target: SSHTarget, snapshot: ProbeSnapshot) => void | Promise<void>;
  /** Invoked when an SSH attempt fails and a retry is about to happen. */
  onRetry?: (target: SSHTarget, attempt: number, err: Error) => void;
  /** Invoked once a host's scan finishes (success or failure). Useful for live progress. */
  onComplete?: (entry: HostScanResult) => void | Promise<void>;
}

export interface HostScanResult {
  target: SSHTarget;
  result?: ScanResult;
  error?: string;
  durationMs: number;
}

/**
 * Run an async function over `items` with at most `concurrency` in flight.
 * Uses a worker pool, not wave batching, so a slow host doesn't block faster
 * ones queued behind it.
 */
export async function runConcurrent<T, R>(
  items: T[],
  concurrency: number,
  fn: (item: T) => Promise<R>,
): Promise<R[]> {
  const results: R[] = new Array(items.length);
  let next = 0;
  const workerCount = Math.min(Math.max(concurrency, 1), items.length);

  async function worker(): Promise<void> {
    while (true) {
      const i = next++;
      if (i >= items.length) return;
      results[i] = await fn(items[i]);
    }
  }

  await Promise.all(Array.from({ length: workerCount }, worker));
  return results;
}

/**
 * Scan multiple remote hosts via SSH.
 *
 * For each target:
 *   1. Establish SSH connection (with retry-on-failure)
 *   2. Upload probe binary matching remote arch
 *   3. Execute probe with the manifest
 *   4. Download snapshot JSON
 *   5. Run local scan engine against the snapshot
 *
 * Returns results for all hosts (including failures).
 */
export async function scanMultipleHosts(
  options: MultiHostScanOptions,
): Promise<HostScanResult[]> {
  const { targets, transportOptions, scanOptions } = options;
  const concurrency = options.concurrency ?? 5;
  const retries = options.retries ?? 0;

  // Import lazily to keep the module tree light when SSH is not used
  const { ScanEngine } = await import('../core/engine.js');
  const { adapterRegistry } = await import('../adapters/registry.js');
  const { checkRegistry } = await import('../core/check-registry.js');
  const { SnapshotFSProvider } = await import('../core/snapshot-fs-provider.js');
  const { executeRemoteProbeWithRetry } = await import('./ssh.js');

  async function processTarget(target: SSHTarget): Promise<HostScanResult> {
    const start = Date.now();
    let entry: HostScanResult;
    try {
      const snapshot = await executeRemoteProbeWithRetry(
        target,
        {
          probeBinDir: transportOptions.probeBinDir,
          manifest: transportOptions.manifest,
          timeout: transportOptions.timeout,
        },
        { retries, onRetry: options.onRetry },
      );

      if (options.onSnapshot) {
        await options.onSnapshot(target, snapshot);
      }

      const snapshotFs = new SnapshotFSProvider(snapshot);
      const engine = new ScanEngine(adapterRegistry, checkRegistry, snapshotFs);
      const result = await engine.scan({
        agentFilter: scanOptions.agentFilter,
      });

      result.host = snapshot.hostname;
      result.label = target.label;

      entry = {
        target,
        result,
        durationMs: Date.now() - start,
      };
    } catch (err) {
      entry = {
        target,
        error: (err as Error).message,
        durationMs: Date.now() - start,
      };
    }

    if (options.onComplete) {
      await options.onComplete(entry);
    }

    return entry;
  }

  return runConcurrent(targets, concurrency, processTarget);
}
