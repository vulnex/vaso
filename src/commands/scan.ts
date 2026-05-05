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
  outputDir?: string;
  saveBaseline?: boolean;
  diff?: boolean;
  allUsers?: boolean;
  color?: boolean;
  silent?: boolean;
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

const FORMAT_EXT: Record<string, string> = {
  terminal: 'txt',
  json: 'json',
  sarif: 'sarif',
  markdown: 'md',
  html: 'html',
  csv: 'csv',
  junit: 'xml',
};

const NON_AGGREGATABLE_FORMATS = new Set(['sarif', 'junit']);

function safeHostname(host: string): string {
  return host.replace(/[^A-Za-z0-9._-]/g, '_');
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

    if (!options.silent) {
      if (snapshot.privilege && !snapshot.privilege.isRoot) {
        console.log(chalk.yellow(`  Warning: snapshot collected as non-root user "${snapshot.privilege.username}" — scan coverage may be limited.\n`));
      }
      console.log(chalk.dim(`  Scanning snapshot from host "${snapshot.hostname}" (${snapshot.platform})\n`));
    }
  }

  // SSH remote scanning
  if (options.host || options.inventory) {
    const { parseSSHTarget } = await import('../transport/ssh.js');
    const { parseInventory } = await import('../transport/inventory.js');
    const { scanMultipleHosts } = await import('../transport/multi-host.js');
    const { buildProbeManifest } = await import('../core/manifest-builder.js');
    type SSHTarget = import('../transport/ssh.js').SSHTarget;

    const silent = !!options.silent;
    const log = (msg: string) => { if (!silent) console.log(msg); };

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

    // Output mode validation
    if (options.output && options.outputDir) {
      console.error(chalk.red('--output and --output-dir are mutually exclusive'));
      process.exitCode = 2;
      return;
    }
    if (silent && !options.output && !options.outputDir) {
      console.error(chalk.red('--silent requires either -o/--output or --output-dir'));
      process.exitCode = 2;
      return;
    }
    if (options.output && NON_AGGREGATABLE_FORMATS.has(options.format)) {
      console.error(chalk.red(
        `--output cannot aggregate ${options.format} across multiple hosts. ` +
        `Use --output-dir <dir> instead — each host will be written as <hostname>.${FORMAT_EXT[options.format]}.`
      ));
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

    log(chalk.bold(`\n  Scanning ${targets.length} remote host(s)...\n`));

    let saveSnapshotDir: string | undefined;
    if (options.saveSnapshot) {
      const { mkdir } = await import('node:fs/promises');
      saveSnapshotDir = options.saveSnapshot;
      await mkdir(saveSnapshotDir, { recursive: true });
    }

    if (options.outputDir) {
      const { mkdir } = await import('node:fs/promises');
      await mkdir(options.outputDir, { recursive: true });
    }

    const reporter = getReporter(options.format as any ?? 'terminal');
    const ext = FORMAT_EXT[options.format] ?? 'txt';

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
              const safeHost = safeHostname(snapshot.hostname ?? target.host);
              const outPath = joinPath(saveSnapshotDir!, `${safeHost}.json`);
              await writeFile(outPath, JSON.stringify(snapshot, null, 2), 'utf-8');
              log(chalk.dim(`  Saved snapshot for ${target.host} → ${outPath}`));
            } catch (err) {
              log(chalk.yellow(`  Warning: failed to save snapshot for ${target.host}: ${(err as Error).message}`));
            }
          }
        : undefined,
      onRetry: (target, attempt, err) => {
        log(chalk.yellow(`  Retry ${attempt}/${retries} for ${target.host}: ${err.message.split('\n')[0]}`));
      },
      onComplete: async (entry) => {
        const label = entry.target.label ?? `${entry.target.user}@${entry.target.host}`;
        const dur = `${entry.durationMs}ms`;
        if (entry.error) {
          log(chalk.red(`  ✗ ${label} (${dur}): ${entry.error.split('\n')[0]}`));
        } else if (entry.result) {
          const findings = entry.result.summary;
          const summary = `${findings.critical}C / ${findings.warning}W / ${findings.info}I`;
          log(chalk.green(`  ✓ ${label} (${dur}) — score ${entry.result.totalScore}/100, ${summary}`));

          if (options.outputDir) {
            try {
              const { join: joinPath } = await import('node:path');
              const safeHost = safeHostname(entry.result.host ?? entry.target.host);
              const outPath = joinPath(options.outputDir, `${safeHost}.${ext}`);
              await writeFile(outPath, reporter.render(entry.result), 'utf-8');
            } catch (err) {
              log(chalk.yellow(`  Warning: failed to write output for ${entry.target.host}: ${(err as Error).message}`));
            }
          }
        }
      },
    });

    // Report results
    const successResults = hostResults.filter(hr => hr.result);
    const failedResults = hostResults.filter(hr => hr.error);

    if (options.outputDir) {
      log(chalk.green(`\n  Wrote ${successResults.length} report(s) to ${options.outputDir}/`));
    } else if (options.output) {
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
      log(chalk.green(`Report written to ${options.output}`));
    } else {
      for (const hr of successResults) {
        if (hr.result) {
          const label = hr.target.label ?? `${hr.target.user}@${hr.target.host}`;
          log(chalk.bold(`\n── ${label} (${hr.result.host ?? hr.target.host}) ──\n`));
          log(reporter.render(hr.result));
        }
      }

      if (failedResults.length > 0) {
        log(chalk.bold(chalk.red(`\n  Failed hosts (${failedResults.length}):`)));
        for (const hr of failedResults) {
          const label = hr.target.label ?? `${hr.target.user}@${hr.target.host}`;
          log(chalk.red(`    ✗ ${label}: ${hr.error}`));
        }
      }

      // Summary
      log(chalk.bold(`\n  Summary: ${successResults.length} scanned, ${failedResults.length} failed\n`));
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

  // Local scan: --silent requires -o (no remote hosts so --output-dir doesn't apply)
  const localSilent = !!options.silent;
  if (localSilent && !options.output) {
    console.error(chalk.red('--silent requires -o/--output for local scans'));
    process.exitCode = 2;
    return;
  }
  const localLog = (msg: string) => { if (!localSilent) console.log(msg); };

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
      localLog(chalk.green(`Baseline saved to ${path}`));
    }

    // Diff against baseline if requested
    if (options.diff) {
      const baseline = await loadBaseline();
      if (baseline) {
        const diff = diffResults(result, baseline);
        localLog(chalk.bold('\nDifferential Scan Results:'));
        localLog(`  New findings: ${chalk.red(String(diff.newFindings.length))}`);
        localLog(`  Resolved: ${chalk.green(String(diff.resolvedFindings.length))}`);
        localLog(`  Unchanged: ${chalk.dim(String(diff.unchangedFindings.length))}`);

        if (diff.newFindings.length > 0) {
          localLog(chalk.bold('\n  New findings:'));
          for (const f of diff.newFindings) {
            localLog(`    ${chalk.red('[NEW]')} ${f.id}: ${f.name} — ${f.message}`);
          }
        }
        if (diff.resolvedFindings.length > 0) {
          localLog(chalk.bold('\n  Resolved:'));
          for (const f of diff.resolvedFindings) {
            localLog(`    ${chalk.green('[RESOLVED]')} ${f.id}: ${f.name}`);
          }
        }
        localLog('');
      } else {
        localLog(chalk.yellow('No baseline found. Run with --save-baseline first.'));
      }
    }

    const reporter = getReporter(scanOptions.format ?? 'terminal');
    const output = reporter.render(result);

    if (options.output) {
      await writeFile(options.output, output, 'utf-8');
      localLog(chalk.green(`Report written to ${options.output}`));
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
