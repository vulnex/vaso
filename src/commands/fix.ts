import chalk from 'chalk';
import { ScanEngine } from '../core/engine.js';
import { adapterRegistry } from '../adapters/registry.js';
import { checkRegistry } from '../core/check-registry.js';
import { RemediationEngine } from '../remediation/engine.js';
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
    await rollback(typeof options.rollback === 'string' ? options.rollback : undefined);
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

    const fixable = result.agents.flatMap(a => a.results.filter(r => !r.passed && r.fixable));
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
    console.log(`\n${chalk.bold('Summary:')} ${applied}/${results.length} fixes applied`);
  } catch (err) {
    logError(chalk.red('Fix failed:'), err);
    process.exitCode = 1;
  }
}
