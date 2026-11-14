import { mkdir, writeFile, chmod, lstat, rm } from 'node:fs/promises';
import { join, dirname, isAbsolute } from 'node:path';
import { homedir } from 'node:os';
import chalk from 'chalk';
import type { ScanResult, FixResult, AgentScanResult, CheckResult } from '../core/types.js';
import { LocalFSProvider } from '../core/local-fs-provider.js';
import type { CheckRegistry } from '../core/check-registry.js';
import type { AdapterRegistry } from '../adapters/registry.js';
import { credentialPathsFor } from '../adapters/adapter.js';
import { getAllSkillsDirs, getSkillFiles } from '../core/utils.js';
import { promptForFix } from './prompt.js';
import { readRegularFile, regularMode, resolvedDir, withChangeRecorder, withFixBoundary, UnsafeTargetError } from './safe-file.js';
import { getUserHomeDirs } from '../adapters/openclaw.js';
import { sha256, appendManifestEntry, type BackupManifest, type ManifestEntry } from './backup-manifest.js';

/**
 * Whether `vaso fix` should act on a result: a failing fixable finding, or a
 * folded generic one (CFG-003/POL-003 counted under an agent check, passing,
 * but still carrying the chmod fix — see duplicate-findings.ts). The fix
 * command and the engine must agree on this, or folded fixes never run.
 */
export function isFixableResult(r: CheckResult): boolean {
  return Boolean(r.fixable) && (!r.passed || Boolean(r.foldedInto));
}

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
    const results = await this.runFixes(scanResult, options);
    await this.discardUnusedBackup(results);
    return results;
  }

  /**
   * A run that changed nothing (every fix already in place, skipped or
   * refused) leaves no backup: `--rollback` would otherwise "restore" that
   * no-op backup and report success while the previous run's fix stays.
   */
  private async discardUnusedBackup(results: FixResult[]): Promise<void> {
    if (results.some(r => r.applied) || this.everChanged) return;
    await rm(this.backupDir, { recursive: true, force: true }).catch(() => undefined);
  }

  /** Whether any fix of this run reached the point of changing a path. */
  private everChanged = false;

  private async runFixes(scanResult: ScanResult, options: FixOptions): Promise<FixResult[]> {
    const results: FixResult[] = [];
    let applyAll = options.yes ?? false;

    // Non-TTY safety: require --yes in non-interactive environments
    if (!applyAll && !options.dryRun && !process.stdin.isTTY) {
      console.log(chalk.yellow('Non-interactive terminal detected. Use --yes to apply fixes in CI/scripts.'));
      return results;
    }

    for (const agent of scanResult.agents) {
      // A folded generic finding (see foldedInto) passes but keeps its fix
      const fixable = agent.results.filter(isFixableResult);

      if (fixable.length === 0) continue;

      console.log(chalk.cyan(`\nAgent: ${agent.agent}`));
      console.log(`  ${fixable.length} fixable issue(s) found\n`);

      for (const finding of fixable) {
        const check = this.checks.getAll().find(c => c.id === finding.id);
        if (!check?.fix) continue;

        if (options.dryRun) {
          console.log(`  ${chalk.yellow('[dry-run]')} ${finding.id}: ${finding.fixDescription ?? 'would fix'}`);
          results.push({ checkId: finding.id, applied: false, skipped: true, message: `Dry run: ${finding.fixDescription}` });
          continue;
        }

        // Interactive prompt when not in auto-apply mode
        if (!applyAll) {
          const response = await promptForFix(finding);

          if (response === 'no') {
            results.push({ checkId: finding.id, applied: false, skipped: true, message: 'Skipped by user' });
            continue;
          }

          if (response === 'quit') {
            results.push({ checkId: finding.id, applied: false, skipped: true, message: 'Skipped by user' });
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
          const credentialPaths = credentialPathsFor(adapter, agent.installation, fs);
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
            // A precautionary backup of a file vaso won't write (a symlink, a
            // hard link…) is skipped: the fix refuses that file itself, and
            // must still fix the others (CFG-003 chmods several files)
            await this.backupFile(file).catch((err: unknown) => {
              if (!(err instanceof UnsafeTargetError)) throw err;
            });
          }
          for (const file of credentialPaths ?? []) {
            await this.backupFile(file).catch(() => undefined);
          }

          // Anything else the fix changes is backed up just before it changes
          // Writes stay inside the owning user's home — where rollback can
          // restore them. An install dir relocated outside it (SAND_DATA_ROOT,
          // CODEX_HOME=/data/…) is refused rather than changed beyond undo
          // (an install outside every home falls back to the scanning user's,
          // so nothing there is writable either — rollback's own boundary)
          const home = (await homeOf(agent.installation.installDir, fs)) ?? homedir();
          const roots = [home];
          // The home's owner, by lstat: a home a user made a symlink must not
          // lend its target's owner (root's, for /etc)
          const ownerUid = await lstat(home).then(s => s.uid, () => undefined);
          const fixResult = await withFixBoundary({ roots, ownerUid }, () => withChangeRecorder(path => { this.changed.add(path); this.everChanged = true; return this.backupFile(path); }, () => check.fix!({
            installation: agent.installation,
            configs: agent.installation.configFiles,
            platform: process.platform,
            fs,
            credentialPaths,
            skillFiles,
          })));

          await this.recordAfterState();
          results.push(fixResult);
          if (fixResult.applied) this.applied.push({ install: installKey(agent), checkId: finding.id, result: fixResult });
          const icon = fixResult.applied ? chalk.green('+') : fixResult.alreadyDone ? chalk.dim('=') : chalk.red('x');
          console.log(`  ${icon} ${finding.id}: ${fixResult.message}`);
        } catch (err) {
          // whatever the failed fix changed before it threw is recorded too
          await this.recordAfterState().catch(() => undefined);
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

  /** Fixes this run applied, by installation. */
  private applied: Array<{ install: string; checkId: string; result: FixResult }> = [];

  /**
   * The applied fixes whose finding a scan taken after the run still reports
   * failing on the same installation: the fix changed something but did not
   * resolve everything (a setting it can't write, an env override, a part
   * left for manual review). `vaso fix` reports these as partially applied.
   */
  stillOpen(rescan: ScanResult): Array<{ checkId: string; result: FixResult; finding: CheckResult }> {
    const open = new Map<string, CheckResult>();
    for (const agent of rescan.agents) {
      for (const r of agent.results) if (!r.passed) open.set(`${installKey(agent)}\0${r.id}`, r);
    }
    return this.applied.flatMap(a => {
      const finding = open.get(`${a.install}\0${a.checkId}`);
      return finding ? [{ checkId: a.checkId, result: a.result, finding }] : [];
    });
  }

  /** The run's backup manifest (see backup-manifest.ts); the first backup of a
   *  path is the original — a later fix on the same file must not replace it. */
  private manifest: BackupManifest = { version: 1, entries: {} };

  /**
   * Back up what a fix may touch: a regular file is copied (with its full
   * mode and hash in the manifest), a directory gets its mode recorded (fixes
   * chmod directories). A symlink, FIFO or device refuses the backup — and so
   * the fix: `vaso fix` never writes through a link or blocks on a pipe.
   * Evidence can name something that is not a path at all (`ps`, a URL).
   */
  private async backupFile(filePath: string): Promise<void> {
    if (!isAbsolute(filePath) || this.manifest.entries[filePath]) return;
    const { mode, dir, uid } = await regularMode(filePath);
    const where = { realDir: await resolvedDir(filePath, dir), uid };
    await this.ensureBackupDir();
    if (dir) {
      this.manifest.entries[filePath] = { kind: 'dir', mode, ...where };
    } else {
      const content = await readRegularFile(filePath).catch((err: NodeJS.ErrnoException) => {
        if (err.code === 'EACCES' || err.code === 'EPERM') return undefined;
        throw err;
      });
      if (content === undefined) {
        this.manifest.entries[filePath] = { kind: 'mode', mode, ...where };
        await appendManifestEntry(this.backupDir, filePath, this.manifest.entries[filePath]);
        this.backedUp.add(filePath);
        return;
      }
      const destDir = join(this.backupDir, dirname(filePath));
      await mkdir(destDir, { recursive: true, mode: 0o700 });
      // Owner-only copy: the original's mode lives in the manifest
      await writeFile(join(this.backupDir, filePath), content, { mode: 0o600, flag: 'wx' });
      this.manifest.entries[filePath] = { kind: 'file', mode, before: sha256(content), ...where };
    }
    await appendManifestEntry(this.backupDir, filePath, this.manifest.entries[filePath]);
    this.backedUp.add(filePath);
  }

  /** Paths changed by the fix that is running: only these can have a new after-state. */
  private changed = new Set<string>();

  /** Paths backed up during the fix that is running (precautionary or not). */
  private backedUp = new Set<string>();

  /**
   * After-state of what the fix backed up: a file it changed is hashed as the
   * fixes left it; one it never changed is recorded as unchanged (after =
   * before), so rollback keeps a later edit to it rather than discarding it.
   */
  private async recordAfterState(): Promise<void> {
    for (const path of this.backedUp) {
      const entry = this.manifest.entries[path];
      if (!entry || this.changed.has(path)) continue;
      const update: Partial<ManifestEntry> = {};
      if (entry.kind === 'file' && entry.after === undefined) update.after = entry.after = entry.before;
      if (entry.afterMode === undefined) update.afterMode = entry.afterMode = entry.mode;
      if (Object.keys(update).length > 0) await appendManifestEntry(this.backupDir, path, update);
    }
    this.backedUp.clear();
    for (const path of this.changed) {
      const entry = this.manifest.entries[path];
      if (!entry) continue;
      const update: Partial<ManifestEntry> = {};
      if (entry.kind === 'file') {
        const after = await readRegularFile(path).then(sha256, () => undefined);
        if (after !== entry.after) update.after = entry.after = after;
      }
      // Mode as the fix left it: rollback restores a mode only where it changed
      const afterMode = await lstat(path).then(s => s.mode & 0o7777, () => undefined);
      if (afterMode !== undefined && afterMode !== entry.afterMode) update.afterMode = entry.afterMode = afterMode;
      if (Object.keys(update).length > 0) await appendManifestEntry(this.backupDir, path, update);
    }
    this.changed.clear();
  }

  private async ensureBackupDir(): Promise<void> {
    // Backups hold copies of secrets: the tree is owner-only. The backups
    // root may predate this, so it is tightened explicitly.
    const backupsRoot = dirname(this.backupDir);
    await mkdir(backupsRoot, { recursive: true, mode: 0o700 });
    if (process.platform !== 'win32') await chmod(backupsRoot, 0o700);
    await mkdir(this.backupDir, { recursive: true, mode: 0o700 });
  }
}

/** One installation across two scans of the same host. */
function installKey(agent: AgentScanResult): string {
  return `${agent.agent}\0${agent.installation.installDir}\0${agent.installation.agentName ?? ''}`;
}

/**
 * The home an installation lives in: the longest user home that contains its
 * directory (every user's home when running as root — `--all-users`), or
 * none for a system-wide install (/etc, /opt), which then is its own boundary.
 */
async function homeOf(installDir: string, fs: LocalFSProvider): Promise<string | undefined> {
  const homes = new Set<string>([homedir()]);
  if (process.getuid?.() === 0) {
    for (const { home } of await getUserHomeDirs(true, fs).catch(() => [])) homes.add(home);
  }
  let best: string | undefined;
  for (const home of homes) {
    const prefix = home.endsWith('/') ? home : `${home}/`;
    if ((installDir === home || installDir.startsWith(prefix)) && (!best || home.length > best.length)) best = home;
  }
  return best;
}
