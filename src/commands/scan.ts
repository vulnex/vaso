import chalk from 'chalk';
import { ScanEngine } from '../core/engine.js';
import { adapterRegistry } from '../adapters/registry.js';
import { checkRegistry } from '../core/check-registry.js';
import { getReporter } from '../reporting/index.js';
import { saveBaseline, loadBaseline, diffResults } from '../core/baseline.js';
import { SnapshotFSProvider } from '../core/snapshot-fs-provider.js';
import type { ProbeSnapshot } from '../core/snapshot-types.js';
import type { ScanOptions } from '../core/types.js';
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
}

export async function runScan(options: ScanCommandOptions): Promise<void> {
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

    // Exit with non-zero if critical findings
    const hasCritical = result.agents.some(a =>
      a.results.some(r => r.severity === 'critical' && !r.passed)
    );
    if (hasCritical) {
      process.exitCode = 1;
    }
  } catch (err) {
    console.error(chalk.red('Scan failed:'), (err as Error).message);
    process.exitCode = 1;
  }
}
