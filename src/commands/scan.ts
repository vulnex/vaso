import chalk from 'chalk';
import { stripColor } from '../reporting/text-safety.js';
import { ScanEngine } from '../core/engine.js';
import { adapterRegistry } from '../adapters/registry.js';
import { checkRegistry } from '../core/check-registry.js';
import { getReporter } from '../reporting/index.js';
import { saveBaseline, loadBaseline, diffResults } from '../core/baseline.js';
import { SnapshotFSProvider } from '../core/snapshot-fs-provider.js';
import { allUsersCoverageWarning } from '../adapters/openclaw.js';
import type { ProbeSnapshot } from '../core/snapshot-types.js';
import { VERSION } from '../version.js';
import { parseRemoteOptions, type RemoteOptionValues } from './remote-options.js';
import { loadSnapshotFile, SnapshotLoadError, snapshotErrorLines, SNAPSHOT_TRUNCATED_WARNING, probeVersionWarning } from '../core/snapshot-load.js';
import type { CheckResult, ScanOptions, ScanResult } from '../core/types.js';
import { shouldFailScan, isValidFailOn, incompleteResults, EXIT_FINDINGS, EXIT_INCOMPLETE, EXIT_USAGE, type FailOnLevel } from '../core/exit-criteria.js';
import { logError } from '../core/debug.js';
import { writeFileEnsureDir, writeFileOwnerOnly } from '../core/utils.js';
import { HostFileNames, safeHostname } from '../transport/host-files.js';
import { writeFile } from 'node:fs/promises';
import { toReportJson } from '../reporting/serialize.js';

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


export async function runScan(options: ScanCommandOptions): Promise<void> {
  const failOn: FailOnLevel = options.failOn && isValidFailOn(options.failOn) ? options.failOn : 'critical';
  if (options.failOn && !isValidFailOn(options.failOn)) {
    console.error(chalk.red(`Invalid --fail-on value "${options.failOn}". Use: critical, warning, info, or none.`));
    process.exitCode = 2;
    return;
  }

  // Top-level --silent / --output-dir gates (apply to all scan modes)
  if (options.output && options.outputDir) {
    console.error(chalk.red('--output and --output-dir are mutually exclusive'));
    process.exitCode = 2;
    return;
  }
  if (options.silent && !options.output && !options.outputDir) {
    console.error(chalk.red('--silent requires -o/--output or --output-dir'));
    process.exitCode = 2;
    return;
  }
  // Snapshots are what a remote scan collects; a local scan has none to save
  if (options.saveSnapshot && !options.host?.length && !options.inventory) {
    console.error(chalk.red('--save-snapshot applies to remote scans only (use with --host or --inventory)'));
    process.exitCode = 2;
    return;
  }
  let remoteValues: RemoteOptionValues;
  try {
    remoteValues = parseRemoteOptions(options);
  } catch (err) {
    console.error(chalk.red((err as Error).message));
    process.exitCode = 2;
    return;
  }

  let snapshotFs: SnapshotFSProvider | undefined;

  if (options.snapshot) {
    let snapshot: ProbeSnapshot;
    try {
      snapshot = await loadSnapshotFile(options.snapshot);
    } catch (err) {
      if (!(err instanceof SnapshotLoadError)) throw err;
      for (const line of snapshotErrorLines(err)) console.error(chalk.red(line));
      process.exitCode = EXIT_USAGE;
      return;
    }

    snapshotFs = new SnapshotFSProvider(snapshot);

    if (!options.silent) {
      if (snapshot.privilege && !snapshot.privilege.isRoot) {
        console.error(chalk.yellow(`  Warning: snapshot collected as non-root user "${snapshot.privilege.username}" — scan coverage may be limited.\n`));
      }
      if (snapshot.truncated) console.error(chalk.yellow(`  Warning: ${SNAPSHOT_TRUNCATED_WARNING}.\n`));
      const probeWarning = probeVersionWarning(snapshot, VERSION);
      if (probeWarning) console.error(chalk.yellow(`  Warning: ${probeWarning}.\n`));
      console.error(chalk.dim(`  Scanning snapshot from host "${snapshot.hostname}" (${snapshot.platform})\n`));
    }
  }

  // SSH remote scanning
  if (options.host || options.inventory) {
    const { parseSSHTarget, uniqueTargets } = await import('../transport/ssh.js');
    const { parseInventory } = await import('../transport/inventory.js');
    const { scanMultipleHosts } = await import('../transport/multi-host.js');
    const { buildProbeManifest } = await import('../core/manifest-builder.js');
    type SSHTarget = import('../transport/ssh.js').SSHTarget;

    const silent = !!options.silent;
    // Progress and status go to stderr; stdout carries only report output.
    const log = (msg: string) => { if (!silent) console.error(msg); };

    const { concurrency, retries, sshTimeoutSec } = remoteValues;

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

    const deduped = uniqueTargets(targets);
    targets = deduped.targets;
    for (const label of deduped.duplicates) log(chalk.yellow(`  ! ${label} is listed more than once — scanning it once`));

    if (targets.length === 0) {
      console.error(chalk.red('No scan targets specified'));
      process.exitCode = EXIT_USAGE;
      return;
    }

    // SARIF/JUnit documents can't be concatenated across hosts; one host is
    // written as-is, several need one file per host.
    if (targets.length > 1 && !options.outputDir && NON_AGGREGATABLE_FORMATS.has(options.format)) {
      console.error(chalk.red(
        `${options.format} can't be combined across ${targets.length} hosts. ` +
        `Use --output-dir <dir> instead — each host will be written as <hostname>.${FORMAT_EXT[options.format]}.`
      ));
      process.exitCode = 2;
      return;
    }

    // Determine probe binary directory
    // Look for probe binaries relative to the VASO installation
    const { dirname, join } = await import('node:path');
    const { fileURLToPath } = await import('node:url');
    const vasoRoot = join(dirname(fileURLToPath(import.meta.url)), '..');
    const probeBinDir = join(vasoRoot, 'probe', 'dist');

    const manifest = buildProbeManifest(adapterRegistry.getAdapters());
    const timeout = sshTimeoutSec * 1000;

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
    // One name per target for its snapshot and its report
    const hostFiles = new HostFileNames();
    const targetLabel = (t: { label?: string; user: string; host: string }) => t.label ?? `${t.user}@${t.host}`;

    const hostResults = await scanMultipleHosts({
      targets,
      transportOptions: { probeBinDir, manifest, timeout },
      scanOptions: {
        agentFilter: options.agent,
        format: options.format as any,
        allUsers: options.allUsers,
      },
      concurrency,
      retries,
      onSnapshot: saveSnapshotDir
        ? async (target, snapshot) => {
            try {
              const { join: joinPath } = await import('node:path');
              const safeHost = hostFiles.claim(snapshot.hostname ?? target.host, targetLabel(target));
              const outPath = joinPath(saveSnapshotDir!, `${safeHost}.json`);
              // Snapshots hold collected file contents by design — owner-only
              await writeFileOwnerOnly(outPath, JSON.stringify(snapshot, null, 2));
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
          // A baseline per scanned host, as for a local or snapshot scan
          // Keyed by the target, not the hostname it reports: two inventory
          // hosts can report the same name and would share one baseline
          const t = entry.target;
          const targetKey = t.label ?? `${t.user ? `${t.user}@` : ''}${t.host}${t.port ? `:${t.port}` : ''}`;
          await applyBaseline(entry.result, { agent: options.agent, host: targetKey }, options, log);
          const findings = entry.result.summary;
          const summary = `${findings.critical}C / ${findings.warning}W / ${findings.info}I`;
          log(chalk.green(`  ✓ ${label} (${dur}) — score ${entry.result.totalScore}/100, ${summary}`));
          for (const w of entry.warnings ?? []) log(chalk.yellow(`    ! ${w}`));

          if (options.outputDir) {
            try {
              const { join: joinPath } = await import('node:path');
              const safeHost = hostFiles.claim(entry.result.host ?? entry.target.host, targetLabel(entry.target));
              const outPath = joinPath(options.outputDir, `${safeHost}.${ext}`);
              await writeFile(outPath, stripColor(reporter.render(entry.result)), 'utf-8');
              log(chalk.dim(`    → ${outPath}`));
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
      const single = hostResults.length === 1 && successResults.length === 1 && successResults[0].result;
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
        combined = toReportJson(aggregate);
      } else if (single) {
        combined = reporter.render(single);
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
      await writeFileEnsureDir(options.output, stripColor(combined));
      log(chalk.green(`Report written to ${options.output}`));
    } else if (options.format === 'json') {
      // Same per-host array as --output, so stdout pipes into jq
      console.log(toReportJson(hostResults.map(hr => ({
        target: { user: hr.target.user, host: hr.target.host, port: hr.target.port, label: hr.target.label },
        durationMs: hr.durationMs,
        error: hr.error,
        result: hr.result,
      }))));
      if (failedResults.length > 0) log(chalk.red(`  ${failedResults.length} host(s) failed — see "error" entries`));
    } else {
      for (const hr of successResults) {
        if (hr.result) {
          const label = hr.target.label ?? `${hr.target.user}@${hr.target.host}`;
          if (hostResults.length > 1) log(chalk.bold(`\n── ${label} (${hr.result.host ?? hr.target.host}) ──\n`));
          console.log(reporter.render(hr.result));
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

    // 3 if any host could not be scanned or a check errored (takes
    // precedence), else 1 when findings meet the --fail-on threshold
    const allResults = successResults.flatMap(hr =>
      hr.result?.agents.flatMap(a => a.results) ?? []
    );
    const erroredChecks = incompleteResults(allResults);
    if (erroredChecks.length > 0) log(chalk.yellow(incompleteNote(erroredChecks)));
    if (failedResults.length > 0 || erroredChecks.length > 0) {
      process.exitCode = EXIT_INCOMPLETE;
    } else if (shouldFailScan(allResults, failOn)) {
      process.exitCode = EXIT_FINDINGS;
    }

    return; // Don't fall through to local scan
  }

  // Local scan (--silent + -o validation already happened at top level)
  const localSilent = !!options.silent;
  const localLog = (msg: string) => { if (!localSilent) console.error(msg); };

  const engine = new ScanEngine(adapterRegistry, checkRegistry, snapshotFs);
  if (options.allUsers) {
    const coverage = allUsersCoverageWarning(snapshotFs);
    if (coverage) localLog(chalk.yellow(`  ! ${coverage}`));
  }

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
      result.host = snapshotFs.hostname();
    }

    // One baseline per scan scope (agent filter, scanned host)
    const baselineScope = { agent: options.agent, host: snapshotFs ? result.host : undefined };

    await applyBaseline(result, baselineScope, options, localLog);

    const reporter = getReporter(scanOptions.format ?? 'terminal');
    const output = reporter.render(result);

    if (options.output) {
      await writeFileEnsureDir(options.output, stripColor(output));
      localLog(chalk.green(`Report written to ${options.output}`));
    } else if (options.outputDir) {
      // Same <dir>/<hostname>.<ext> layout as multi-host scans, for the local host
      const { join: joinPath } = await import('node:path');
      const { hostname } = await import('node:os');
      const ext = FORMAT_EXT[scanOptions.format ?? 'terminal'] ?? 'txt';
      // A snapshot scan reports on the snapshot's host, not this machine
      const outPath = joinPath(options.outputDir, `${safeHostname(result.host ?? hostname())}.${ext}`);
      await writeFileEnsureDir(outPath, stripColor(output));
      localLog(chalk.green(`Report written to ${outPath}`));
    } else {
      console.log(output);
    }

    // 3 when a check or adapter errored (findings may be missing), else 1
    // when findings meet the --fail-on threshold (default: critical only)
    const allResults = result.agents.flatMap(a => a.results);
    const erroredChecks = incompleteResults(allResults);
    if (erroredChecks.length > 0) {
      localLog(chalk.yellow(incompleteNote(erroredChecks)));
      process.exitCode = EXIT_INCOMPLETE;
    } else if (shouldFailScan(allResults, failOn)) {
      process.exitCode = EXIT_FINDINGS;
    }
  } catch (err) {
    logError(chalk.red('Scan failed:'), err);
    process.exitCode = EXIT_USAGE;
  }
}

/** Stderr note for a scan whose checks did not all complete (exit 3). */
function incompleteNote(errored: readonly CheckResult[]): string {
  const ids = [...new Set(errored.map(r => r.id))];
  return `  Scan incomplete: ${errored.length} check result(s) errored (${ids.slice(0, 5).join(', ')}${ids.length > 5 ? ', …' : ''}) — findings may be missing`;
}

/**
 * `--diff` against the scope's previous baseline (loaded before
 * `--save-baseline` replaces it, or a combined run would compare the scan
 * with itself), then `--save-baseline`. One baseline per agent filter and
 * scanned host; remote hosts each get their own.
 */
async function applyBaseline(
  result: ScanResult,
  baselineScope: { agent?: string; host?: string },
  options: Pick<ScanCommandOptions, 'diff' | 'saveBaseline'>,
  localLog: (msg: string) => void,
): Promise<void> {
  if (options.diff) {
    let baseline = await loadBaseline(baselineScope);
    let mismatched = false;
    // A pre-1.3.1 latest.json may have been saved with -a for other agents:
    // comparing it with this scan would show everything as new or resolved
    const types = (r: ScanResult) => [...new Set(r.agents.map(a => a.agent))].sort().join(',');
    if (baseline && baseline.vasoVersion === undefined && types(baseline) !== types(result)) {
      localLog(chalk.yellow(`The saved baseline covers other agents (${types(baseline) || 'none'}) — not compared. Run with --save-baseline to start a new one.`));
      baseline = null;
      mismatched = true;
    }
    if (baseline) {
      const diff = diffResults(result, baseline);
      result.baselineDiff = {
        baselineTimestamp: baseline.timestamp,
        newFindings: diff.newFindings.map(f => f.id),
        resolvedFindings: diff.resolvedFindings.map(f => f.id),
        unchanged: diff.unchangedFindings.length,
      };
      localLog(chalk.bold('\nDifferential Scan Results:'));
      if (baseline.vasoVersion !== result.vasoVersion) {
        localLog(chalk.dim(`  Baseline taken with VASO ${baseline.vasoVersion ?? '< 1.3.1'}; checks added or changed since may show as new or resolved.`));
      }
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
    } else if (!mismatched) {
      localLog(chalk.yellow('No baseline found. Run with --save-baseline first.'));
    }
  }

  if (options.saveBaseline) {
    const path = await saveBaseline({ ...result, baselineDiff: undefined }, baselineScope);
    localLog(chalk.green(`Baseline saved to ${path}`));
  }
}
