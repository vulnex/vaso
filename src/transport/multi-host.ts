/**
 * Multi-host scanning orchestrator.
 *
 * Connects to each SSH target, uploads the probe binary,
 * collects a snapshot, and runs the scan engine against it.
 */

import type { SSHTarget } from './ssh.js';
import type { ProbeManifest } from '../core/snapshot-types.js';
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
}

export interface HostScanResult {
  target: SSHTarget;
  result?: ScanResult;
  error?: string;
  durationMs: number;
}

/**
 * Scan multiple remote hosts in parallel via SSH.
 *
 * For each target:
 *   1. Establish SSH connection
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

  // Import lazily to keep the module tree light when SSH is not used
  const { ScanEngine } = await import('../core/engine.js');
  const { adapterRegistry } = await import('../adapters/registry.js');
  const { checkRegistry } = await import('../core/check-registry.js');
  const { SnapshotFSProvider } = await import('../core/snapshot-fs-provider.js');

  const results: HostScanResult[] = [];

  // Process hosts concurrently with a concurrency limit
  const CONCURRENCY = 5;
  const queue = [...targets];

  async function processTarget(target: SSHTarget): Promise<HostScanResult> {
    const start = Date.now();
    try {
      const { executeRemoteProbe } = await import('./ssh.js');

      const snapshot = await executeRemoteProbe(target, {
        probeBinDir: transportOptions.probeBinDir,
        manifest: transportOptions.manifest,
        timeout: transportOptions.timeout,
      });

      const snapshotFs = new SnapshotFSProvider(snapshot);
      const engine = new ScanEngine(adapterRegistry, checkRegistry, snapshotFs);
      const result = await engine.scan({
        agentFilter: scanOptions.agentFilter,
      });

      result.host = snapshot.hostname;
      result.label = target.label;

      return {
        target,
        result,
        durationMs: Date.now() - start,
      };
    } catch (err) {
      return {
        target,
        error: (err as Error).message,
        durationMs: Date.now() - start,
      };
    }
  }

  // Simple concurrency pool
  for (let i = 0; i < queue.length; i += CONCURRENCY) {
    const batch = queue.slice(i, i + CONCURRENCY);
    const batchResults = await Promise.all(batch.map(processTarget));
    results.push(...batchResults);
  }

  return results;
}
