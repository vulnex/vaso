import chalk from 'chalk';
import { ScanEngine } from '../core/engine.js';
import { adapterRegistry } from '../adapters/registry.js';
import { checkRegistry } from '../core/check-registry.js';
import { getReporter } from '../reporting/index.js';
import { saveBaseline, loadBaseline, diffResults } from '../core/baseline.js';
import { SnapshotFSProvider } from '../core/snapshot-fs-provider.js';
import type { ProbeSnapshot } from '../core/snapshot-types.js';
import type { ScanOptions } from '../core/types.js';
import { shouldFailScan, isValidFailOn, type FailOnLevel } from '../core/exit-criteria.js';
import { logError } from '../core/debug.js';
import { readFile, writeFile } from 'node:fs/promises';

export interface ScanCommandOptions {
  agent?: string;
  format: string;
  output?: string;
  saveBaseline?: boolean;
  diff?: boolean;
  allUsers?: boolean;
  color?: boolean;
  snapshot?: string;
  host?: string[];
  inventory?: string;
  sshKey?: string;
  sshTimeout?: string;
  sshRetries?: string;
  parallel?: string;
  saveSnapshot?: string;
  sudo?: boolean;
  failOn?: string;
}

function parsePositiveInt(raw: string | undefined, fallback: number, label: string): number {
  if (raw === undefined) return fallback;
  const n = parseInt(raw, 10);
  if (isNaN(n) || n < 0) {
    throw new Error(`Invalid ${label} value "${raw}": expected a non-negative integer`);
  }
  return n;
}

export async function runScan(options: ScanCommandOptions): Promise<void> {
  const failOn: FailOnLevel = options.failOn && isValidFailOn(options.failOn) ? options.failOn : 'critical';
  if (options.failOn && !isValidFailOn(options.failOn)) {
    console.error(chalk.red(`Invalid --fail-on value "${options.failOn}". Use: critical, warning, info, or none.`));
    process.exitCode = 2;
    return;
  }

  let snapshotFs: SnapshotFSProvider | undefined;

  if (options.snapshot) {
    const raw = await readFile(options.snapshot, 'utf-8');
    const snapshot = JSON.parse(raw) as ProbeSnapshot;

    // Validate required fields
    const errors: string[] = [];
    if (snapshot.version !== 1) errors.push(`Unsupported snapshot version: ${snapshot.version}`);
    if (!snapshot.platform) errors.push('Missing platform field');
    if (!snapshot.hostname) errors.push('Missing hostname field');
    if (!snapshot.files || typeof snapshot.files !== 'object') errors.push('Missing or invalid files field');
    if (!snapshot.directories || typeof snapshot.directories !== 'object') errors.push('Missing or invalid directories field');
    if (!snapshot.commandOutputs || typeof snapshot.commandOutputs !== 'object') errors.push('Missing or invalid commandOutputs field');

    if (errors.length > 0) {
      console.error(chalk.red('Invalid snapshot file:'));
      for (const e of errors) console.error(chalk.red(`  - ${e}`));
      process.exitCode = 1;
      return;
    }

    snapshotFs = new SnapshotFSProvider(snapshot);

    if (snapshot.privilege && !snapshot.privilege.isRoot) {
      console.log(chalk.yellow(`  Warning: snapshot collected as non-root user "${snapshot.privilege.username}" — scan coverage may be limited.\n`));
    }

    console.log(chalk.dim(`  Scanning snapshot from host "${snapshot.hostname}" (${snapshot.platform})\n`));
  }

  // SSH remote scanning
  if (options.host || options.inventory) {
    const { parseSSHTarget } = await import('../transport/ssh.js');
    const { parseInventory } = await import('../transport/inventory.js');
    const { scanMultipleHosts } = await import('../transport/multi-host.js');
    const { buildProbeManifest } = await import('../core/manifest-builder.js');
    type SSHTarget = import('../transport/ssh.js').SSHTarget;

    let concurrency: number;
    let retries: number;
    try {
      concurrency = parsePositiveInt(options.parallel, 5, '--parallel');
      retries = parsePositiveInt(options.sshRetries, 0, '--ssh-retries');
      if (concurrency === 0) throw new Error('--parallel must be at least 1');
    } catch (err) {
      console.error(chalk.red((err as Error).message));
      process.exitCode = 2;
      return;
    }

    // Build target list
    let targets: SSHTarget[] = [];

    if (options.host) {
      targets = options.host.map(h => {
        const t = parseSSHTarget(h);
        if (options.sshKey) t.identity = options.sshKey;
        if (options.sudo) t.sudo = true;
        return t;
      });
    }

    if (options.inventory) {
      const inventoryTargets = await parseInventory(options.inventory);
      // Apply CLI overrides
      for (const t of inventoryTargets) {
        if (options.sshKey && !t.identity) t.identity = options.sshKey;
        if (options.sudo) t.sudo = true;
      }
      targets.push(...inventoryTargets);
    }

    if (targets.length === 0) {
      console.error(chalk.red('No scan targets specified'));
      process.exitCode = 1;
      return;
    }

    // Determine probe binary directory
    // Look for probe binaries relative to the VASO installation
    const { dirname, join } = await import('node:path');
    const { fileURLToPath } = await import('node:url');
    const vasoRoot = join(dirname(fileURLToPath(import.meta.url)), '..');
    const probeBinDir = join(vasoRoot, 'probe', 'dist');

    const manifest = buildProbeManifest(adapterRegistry.getAdapters());
    const timeout = parseInt(options.sshTimeout ?? '60', 10) * 1000;

    console.log(chalk.bold(`\n  Scanning ${targets.length} remote host(s)...\n`));

    let saveSnapshotDir: string | undefined;
    if (options.saveSnapshot) {
      const { mkdir } = await import('node:fs/promises');
      saveSnapshotDir = options.saveSnapshot;
      await mkdir(saveSnapshotDir, { recursive: true });
    }

    const hostResults = await scanMultipleHosts({
      targets,
      transportOptions: { probeBinDir, manifest, timeout },
      scanOptions: {
        agentFilter: options.agent,
        format: options.format as any,
      },
      concurrency,
      retries,
      onSnapshot: saveSnapshotDir
        ? async (target, snapshot) => {
            try {
              const { join: joinPath } = await import('node:path');
              const safeHost = (snapshot.hostname ?? target.host).replace(/[^A-Za-z0-9._-]/g, '_');
              const outPath = joinPath(saveSnapshotDir!, `${safeHost}.json`);
              await writeFile(outPath, JSON.stringify(snapshot, null, 2), 'utf-8');
              console.log(chalk.dim(`  Saved snapshot for ${target.host} → ${outPath}`));
            } catch (err) {
              console.log(chalk.yellow(`  Warning: failed to save snapshot for ${target.host}: ${(err as Error).message}`));
            }
          }
        : undefined,
      onRetry: (target, attempt, err) => {
        console.log(chalk.yellow(`  Retry ${attempt}/${retries} for ${target.host}: ${err.message.split('\n')[0]}`));
      },
    });

    // Report results
    const reporter = getReporter(options.format as any ?? 'terminal');
    const successResults = hostResults.filter(hr => hr.result);
    const failedResults = hostResults.filter(hr => hr.error);

    if (options.output) {
      // Aggregate to a single file. JSON gets a structured per-host array;
      // text formats get the per-host renders concatenated with a plain
      // divider so the file is readable without ANSI escapes.
      let combined: string;
      if (options.format === 'json') {
        const aggregate = hostResults.map(hr => ({
          target: {
            user: hr.target.user,
            host: hr.target.host,
            port: hr.target.port,
            label: hr.target.label,
          },
          durationMs: hr.durationMs,
          error: hr.error,
          result: hr.result,
        }));
        combined = JSON.stringify(aggregate, null, 2);
      } else {
        const sections: string[] = [];
        for (const hr of successResults) {
          if (!hr.result) continue;
          const label = hr.target.label ?? `${hr.target.user}@${hr.target.host}`;
          sections.push(`── ${label} (${hr.result.host ?? hr.target.host}) ──\n\n${reporter.render(hr.result)}`);
        }
        if (failedResults.length > 0) {
          const failLines = failedResults.map(hr => {
            const label = hr.target.label ?? `${hr.target.user}@${hr.target.host}`;
            return `  ✗ ${label}: ${hr.error}`;
          });
          sections.push(`Failed hosts (${failedResults.length}):\n${failLines.join('\n')}`);
        }
        sections.push(`Summary: ${successResults.length} scanned, ${failedResults.length} failed`);
        combined = sections.join('\n\n');
      }
      await writeFile(options.output, combined, 'utf-8');
      console.log(chalk.green(`Report written to ${options.output}`));
    } else {
      for (const hr of successResults) {
        if (hr.result) {
          const label = hr.target.label ?? `${hr.target.user}@${hr.target.host}`;
          console.log(chalk.bold(`\n── ${label} (${hr.result.host ?? hr.target.host}) ──\n`));
          console.log(reporter.render(hr.result));
        }
      }

      if (failedResults.length > 0) {
        console.log(chalk.bold(chalk.red(`\n  Failed hosts (${failedResults.length}):`)));
        for (const hr of failedResults) {
          const label = hr.target.label ?? `${hr.target.user}@${hr.target.host}`;
          console.log(chalk.red(`    ✗ ${label}: ${hr.error}`));
        }
      }

      // Summary
      console.log(chalk.bold(`\n  Summary: ${successResults.length} scanned, ${failedResults.length} failed\n`));
    }

    // Exit non-zero if any host failed, or if findings meet the --fail-on threshold
    const allResults = successResults.flatMap(hr =>
      hr.result?.agents.flatMap(a => a.results) ?? []
    );
    if (shouldFailScan(allResults, failOn) || failedResults.length > 0) {
      process.exitCode = 1;
    }

    return; // Don't fall through to local scan
  }

  const engine = new ScanEngine(adapterRegistry, checkRegistry, snapshotFs);

  const scanOptions: ScanOptions = {
    agentFilter: options.agent,
    format: options.format as 'terminal' | 'json' | 'sarif' | 'markdown' | 'html',
    saveBaseline: options.saveBaseline,
    diff: options.diff,
    allUsers: options.allUsers,
  };

  try {
    const result = await engine.scan(scanOptions);

    // Set host from snapshot if scanning from snapshot
    if (snapshotFs) {
      result.host = snapshotFs.hostname;
    }

    // Save baseline if requested
    if (options.saveBaseline) {
      const path = await saveBaseline(result);
      console.log(chalk.green(`Baseline saved to ${path}`));
    }

    // Diff against baseline if requested
    if (options.diff) {
      const baseline = await loadBaseline();
      if (baseline) {
        const diff = diffResults(result, baseline);
        console.log(chalk.bold('\nDifferential Scan Results:'));
        console.log(`  New findings: ${chalk.red(String(diff.newFindings.length))}`);
        console.log(`  Resolved: ${chalk.green(String(diff.resolvedFindings.length))}`);
        console.log(`  Unchanged: ${chalk.dim(String(diff.unchangedFindings.length))}`);

        if (diff.newFindings.length > 0) {
          console.log(chalk.bold('\n  New findings:'));
          for (const f of diff.newFindings) {
            console.log(`    ${chalk.red('[NEW]')} ${f.id}: ${f.name} — ${f.message}`);
          }
        }
        if (diff.resolvedFindings.length > 0) {
          console.log(chalk.bold('\n  Resolved:'));
          for (const f of diff.resolvedFindings) {
            console.log(`    ${chalk.green('[RESOLVED]')} ${f.id}: ${f.name}`);
          }
        }
        console.log('');
      } else {
        console.log(chalk.yellow('No baseline found. Run with --save-baseline first.'));
      }
    }

    const reporter = getReporter(scanOptions.format ?? 'terminal');
    const output = reporter.render(result);

    if (options.output) {
      await writeFile(options.output, output, 'utf-8');
      console.log(chalk.green(`Report written to ${options.output}`));
    } else {
      console.log(output);
    }

    // Exit non-zero if findings meet the --fail-on threshold (default: critical only)
    const allResults = result.agents.flatMap(a => a.results);
    if (shouldFailScan(allResults, failOn)) {
      process.exitCode = 1;
    }
  } catch (err) {
    logError(chalk.red('Scan failed:'), err);
    process.exitCode = 1;
  }
}
