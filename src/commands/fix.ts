import chalk from 'chalk';
import { ScanEngine } from '../core/engine.js';
import { adapterRegistry } from '../adapters/registry.js';
import { checkRegistry } from '../core/check-registry.js';
import { RemediationEngine, isFixableResult } from '../remediation/engine.js';
import { rollback } from '../remediation/rollback.js';
import { logError } from '../core/debug.js';

export interface FixCommandOptions {
  agent?: string;
  dryRun?: boolean;
  yes?: boolean;
  /** true = the latest backup; a string names one (timestamp or part of it). */
  rollback?: boolean | string;
}

export async function runFix(options: FixCommandOptions): Promise<void> {
  // `--rollback ""` is falsy but still a rollback request: it must never fall
  // through to applying fixes.
  if (options.rollback !== undefined && options.rollback !== false) {
    if (options.rollback === '') {
      console.error(chalk.red('--rollback needs a backup name, or no value for the latest one'));
      process.exitCode = 2;
      return;
    }
    await rollback(typeof options.rollback === 'string' ? options.rollback : undefined, { dryRun: options.dryRun });
    return;
  }

  // Nothing to prompt on: refuse up front (a usage error), not after a scan
  // with a 0 exit that reads as "fixed"
  if (!options.yes && !options.dryRun && !process.stdin.isTTY) {
    console.error(chalk.red('Non-interactive terminal: use --yes to apply fixes (or --dry-run to preview them)'));
    process.exitCode = 2;
    return;
  }

  try {
    // First, run a scan
    const engine = new ScanEngine(adapterRegistry, checkRegistry);
    const result = await engine.scan({ agentFilter: options.agent });

    if (result.agents.length === 0) {
      console.log(chalk.yellow('No agents detected. Nothing to fix.'));
      return;
    }

    const fixable = result.agents.flatMap(a => a.results.filter(isFixableResult));
    if (fixable.length === 0) {
      console.log(chalk.green('No fixable issues found.'));
      return;
    }

    console.log(chalk.bold(`Found ${fixable.length} fixable issue(s)`));

    if (options.dryRun) {
      console.log(chalk.dim('(dry run — no changes will be made)\n'));
    }

    const remediation = new RemediationEngine(checkRegistry, adapterRegistry);
    const results = await remediation.fix(result, {
      dryRun: options.dryRun,
      yes: options.yes,
    });

    const applied = results.filter(r => r.applied).length;
    const done = results.filter(r => !r.applied && r.alreadyDone).length;
    const skipped = results.filter(r => !r.applied && r.skipped).length;
    const failed = results.length - applied - done - skipped;

    // An applied fix is only "fixed" when the finding is gone: scan again
    // and name the ones still reported
    let partial = 0;
    if (applied > 0 && !options.dryRun) {
      const rescan = await engine.scan({ agentFilter: options.agent });
      const open = remediation.stillOpen(rescan);
      partial = open.length;
      if (open.length > 0) {
        console.log(`\n${chalk.yellow('Partially applied')} — still reported after the fix:`);
        for (const o of open) {
          console.log(`  ${chalk.yellow('~')} ${o.checkId} (${o.finding.severity}): ${o.finding.message}`);
        }
      }
    }

    const parts = [partial > 0 ? `${applied} applied (${partial} partially — finding still open)` : `${applied} applied`];
    if (done) parts.push(`${done} already in place`);
    if (skipped) parts.push(options.dryRun ? `${skipped} would be applied` : `${skipped} skipped`);
    if (failed) parts.push(`${failed} not applied`);
    console.log(`\n${chalk.bold('Summary:')} ${parts.join(', ')}`);
    // A fix that was refused or failed leaves its finding open
    if (failed > 0) process.exitCode = 1;
  } catch (err) {
    logError(chalk.red('Fix failed:'), err);
    process.exitCode = 1;
  }
}
