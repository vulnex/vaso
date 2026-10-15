import { mkdir, copyFile, readFile, writeFile, stat, chmod } from 'node:fs/promises';
import { join, dirname, isAbsolute } from 'node:path';
import { homedir } from 'node:os';
import { constants as fsConstants } from 'node:fs';
import chalk from 'chalk';
import type { ScanResult, FixResult, AgentScanResult, CheckResult } from '../core/types.js';
import { LocalFSProvider } from '../core/local-fs-provider.js';
import type { CheckRegistry } from '../core/check-registry.js';
import type { AdapterRegistry } from '../adapters/registry.js';
import { getAllSkillsDirs, getSkillFiles } from '../core/utils.js';
import { promptForFix } from './prompt.js';

export interface FixOptions {
  dryRun?: boolean;
  yes?: boolean;
}

export class RemediationEngine {
  private backupDir: string;

  constructor(private checks: CheckRegistry, private adapters?: AdapterRegistry) {
    this.backupDir = join(homedir(), '.vaso', 'backups', new Date().toISOString().replace(/[:.]/g, '-'));
  }

  async fix(scanResult: ScanResult, options: FixOptions): Promise<FixResult[]> {
    const results: FixResult[] = [];
    let applyAll = options.yes ?? false;

    // Non-TTY safety: require --yes in non-interactive environments
    if (!applyAll && !options.dryRun && !process.stdin.isTTY) {
      console.log(chalk.yellow('Non-interactive terminal detected. Use --yes to apply fixes in CI/scripts.'));
      return results;
    }

    for (const agent of scanResult.agents) {
      // A folded generic finding (see foldedInto) passes but keeps its fix
      const fixable = agent.results.filter(r => r.fixable && (!r.passed || r.foldedInto));

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

        // Interactive prompt when not in auto-apply mode
        if (!applyAll) {
          const response = await promptForFix(finding);

          if (response === 'no') {
            results.push({ checkId: finding.id, applied: false, message: 'Skipped by user' });
            continue;
          }

          if (response === 'quit') {
            results.push({ checkId: finding.id, applied: false, message: 'Skipped by user' });
            return results;
          }

          if (response === 'all') {
            applyAll = true;
          }
          // 'yes' and 'all' fall through to apply
        }

        try {
          // Rebuild the full ScanContext the engine produced at scan time —
          // credentialPaths and skillFiles are adapter-derived and aren't
          // persisted on AgentScanResult, so without re-deriving them here
          // fixes like CFG-003 (chmod credential file) silently no-op
          // because their ctx.credentialPaths is empty.
          const fs = new LocalFSProvider();
          const adapter = this.adapters?.getAdapter(agent.installation.agent);
          const credentialPaths = adapter?.getCredentialPaths?.(agent.installation.installDir, fs);
          const skillsDirs = getAllSkillsDirs(agent.installation);
          const skillFiles = skillsDirs.length > 0
            ? (await Promise.all(skillsDirs.map(d => getSkillFiles(d, fs)))).flat()
            : undefined;

          // Back up the evidence files, every config file of the installation
          // (config fixes write to the first config, not necessarily one the
          // evidence names) and the credential paths (permission fixes chmod
          // all of them, including files another check reported) — whatever
          // a fix may touch, so the rollback is exact. Missing paths are skipped.
          const toBackUp = new Set<string>();
          for (const e of finding.evidence ?? []) if (e.file) toBackUp.add(e.file);
          for (const c of agent.installation.configFiles ?? []) toBackUp.add(c.filePath);
          for (const file of toBackUp) {
            await this.backupFile(file);
          }
          for (const file of credentialPaths ?? []) {
            await this.backupFile(file).catch(() => undefined);
          }

          const fixResult = await check.fix({
            installation: agent.installation,
            configs: agent.installation.configFiles,
            platform: process.platform,
            fs,
            credentialPaths,
            skillFiles,
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

  /** Files already backed up in this run: the first copy (the original) wins —
   *  a later fix on the same file must not overwrite it with fixed content. */
  private backedUp = new Set<string>();

  private async backupFile(filePath: string): Promise<void> {
    // Evidence can name a directory (permission fixes) or something that is
    // not a path at all (`ps`, an advisory URL); only regular files are copied.
    // A missing file still fails the backup (and so blocks the fix).
    if (!isAbsolute(filePath) || this.backedUp.has(filePath)) return;
    if ((await stat(filePath)).isDirectory()) return;
    this.backedUp.add(filePath);
    // Backups keep the originals' modes (rollback restores them), so a copy
    // of a world-readable .env stays world-readable — the tree must be
    // owner-only. `mode` applies to every directory mkdir creates; the
    // backups root may predate this, so it is tightened explicitly.
    const backupsRoot = dirname(this.backupDir);
    await mkdir(backupsRoot, { recursive: true, mode: 0o700 });
    if (process.platform !== 'win32') await chmod(backupsRoot, 0o700);
    const destDir = join(this.backupDir, dirname(filePath));
    await mkdir(destDir, { recursive: true, mode: 0o700 });
    // COPYFILE_EXCL: the first copy is the original; a later fix in the same
    // run must not replace it with an already-fixed file.
    await copyFile(filePath, join(this.backupDir, filePath), fsConstants.COPYFILE_EXCL).catch((err: NodeJS.ErrnoException) => {
      if (err.code !== 'EEXIST') throw err;
    });
  }
}
