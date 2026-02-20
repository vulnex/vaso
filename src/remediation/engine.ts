import { mkdir, copyFile, readFile, writeFile } from 'node:fs/promises';
import { join, dirname } from 'node:path';
import { homedir } from 'node:os';
import chalk from 'chalk';
import type { ScanResult, FixResult, AgentScanResult, CheckResult } from '../core/types.js';
import type { CheckRegistry } from '../core/check-registry.js';

export interface FixOptions {
  dryRun?: boolean;
  yes?: boolean;
}

export class RemediationEngine {
  private backupDir: string;

  constructor(private checks: CheckRegistry) {
    this.backupDir = join(homedir(), '.vaso', 'backups', new Date().toISOString().replace(/[:.]/g, '-'));
  }

  async fix(scanResult: ScanResult, options: FixOptions): Promise<FixResult[]> {
    const results: FixResult[] = [];

    for (const agent of scanResult.agents) {
      const fixable = agent.results.filter(r => !r.passed && r.fixable);

      if (fixable.length === 0) continue;

      console.log(chalk.cyan(`\nAgent: ${agent.agent}`));
      console.log(`  ${fixable.length} fixable issue(s) found\n`);

      for (const finding of fixable) {
        const check = this.checks.getAll().find(c => c.id === finding.id);
        if (!check?.fix) continue;

        if (options.dryRun) {
          console.log(`  ${chalk.yellow('[dry-run]')} ${finding.id}: ${finding.fixDescription ?? 'would fix'}`);
          results.push({ checkId: finding.id, applied: false, message: `Dry run: ${finding.fixDescription}` });
          continue;
        }

        try {
          // Backup affected files
          if (finding.evidence) {
            for (const e of finding.evidence) {
              await this.backupFile(e.file);
            }
          }

          const fixResult = await check.fix({
            installation: agent.installation,
            configs: agent.installation.configFiles,
            platform: process.platform,
          });

          results.push(fixResult);
          const icon = fixResult.applied ? chalk.green('+') : chalk.red('x');
          console.log(`  ${icon} ${finding.id}: ${fixResult.message}`);
        } catch (err) {
          results.push({
            checkId: finding.id,
            applied: false,
            message: `Fix failed: ${(err as Error).message}`,
          });
          console.log(`  ${chalk.red('x')} ${finding.id}: Fix failed — ${(err as Error).message}`);
        }
      }
    }

    return results;
  }

  private async backupFile(filePath: string): Promise<void> {
    try {
      const destDir = join(this.backupDir, dirname(filePath));
      await mkdir(destDir, { recursive: true });
      await copyFile(filePath, join(this.backupDir, filePath));
    } catch {
      // Best-effort backup
    }
  }
}
