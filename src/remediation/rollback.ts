import { readdir, readFile, writeFile, stat, lstat, rename } from 'node:fs/promises';
import { readRegularFile, writeRegularFile, chmodNoFollow, movedSinceBackup, withFixBoundary, assertCreatable } from './safe-file.js';
import { MANIFEST_NAME, readManifest, sha256, type ManifestEntry } from './backup-manifest.js';
import { join } from 'node:path';
import { readFileSync, readdirSync } from 'node:fs';
import { homedir } from 'node:os';
import chalk from 'chalk';
import { pathExists } from '../core/utils.js';

/**
 * Where a rollback may write: the scanning user's home, and as root every
 * local user's home (`sudo vaso fix --all-users` fixes their files). A backup
 * tree is just files under ~/.vaso/backups — a tampered one must not make
 * rollback write elsewhere, or through a symlinked directory out of a home.
 */
function rollbackRoots(): string[] {
  const roots = [homedir()];
  if (process.getuid?.() !== 0) return roots;
  try {
    for (const line of readFileSync('/etc/passwd', 'utf-8').split('\n')) {
      const f = line.split(':');
      if (f.length >= 6 && f[5].startsWith('/') && f[5] !== '/' && !/nologin|false$/.test(f[6] ?? '')) roots.push(f[5]);
    }
  } catch {}
  try {
    for (const u of readdirSync('/Users')) if (!u.startsWith('.') && u !== 'Shared') roots.push(join('/Users', u));
  } catch {}
  return [...new Set(roots)];
}

/** A backup already restored: kept, but no longer "the last fix run". */
const RESTORED_PREFIX = 'restored-';

/**
 * Restore files from a VASO backup directory.
 * If no timestamp is given, uses the most recent backup not yet restored —
 * so repeated rollbacks undo fix runs one at a time, newest first.
 */
export async function rollback(timestamp?: string, options: { dryRun?: boolean } = {}): Promise<void> {
  const dryRun = options.dryRun === true;
  const backupsDir = join(homedir(), '.vaso', 'backups');

  if (!await pathExists(backupsDir)) {
    console.log(chalk.yellow('No backups found at ~/.vaso/backups/'));
    return;
  }

  const entries = await readdir(backupsDir, { withFileTypes: true });
  const dirs = entries.filter(e => e.isDirectory()).map(e => e.name).sort();
  const pending = dirs.filter(d => !d.startsWith(RESTORED_PREFIX));

  if (dirs.length === 0 || (!timestamp && pending.length === 0)) {
    console.log(chalk.yellow(dirs.length === 0
      ? 'No backup directories found.'
      : 'Every backup has already been restored. Name one to restore it again: vaso fix --rollback <backup>'));
    if (dirs.length > 0) console.log(`Available backups: ${dirs.join(', ')}`);
    return;
  }

  // The last fix run is the newest pending backup that holds a change: a
  // no-op run's backup from an older version (nothing applied) is skipped
  let latest: string | undefined;
  if (!timestamp) {
    for (let i = pending.length - 1; i >= 0 && !latest; i--) {
      if (!(await isEmptyBackup(join(backupsDir, pending[i])))) latest = pending[i];
      else console.log(chalk.dim(`Skipping backup ${pending[i]}: its fix run changed nothing`));
    }
    if (!latest) {
      console.log(chalk.yellow('No pending backup records a change — nothing to roll back.'));
      return;
    }
  }

  const exact = timestamp ? dirs.filter(d => d === timestamp || d === `${RESTORED_PREFIX}${timestamp}`) : [];
  const matches = !timestamp ? [latest]
    : exact.length > 0 ? exact
    : dirs.filter(d => d.includes(timestamp));
  const target = matches.length === 1 ? matches[0] : undefined;

  if (!target) {
    console.log(chalk.red(matches.length > 1
      ? `"${timestamp}" matches ${matches.length} backups — be more specific.`
      : `No backup matching "${timestamp}" found.`));
    console.log(`Available backups: ${dirs.join(', ')}`);
    process.exitCode = 2;
    return;
  }

  const backupDir = join(backupsDir, target);
  console.log(chalk.cyan(`${dryRun ? 'Would restore' : 'Restoring'} from backup: ${target}`));
  if (dryRun) console.log(chalk.dim('(dry run — no changes will be made)'));

  // Collect all files recursively from the backup directory
  const manifest = await readManifest(backupDir);
  const files = (await collectFiles(backupDir)).filter(f => f !== join(backupDir, MANIFEST_NAME));
  const dirModes = Object.entries(manifest?.entries ?? {}).filter(([, e]) => e.kind === 'dir' || e.kind === 'mode');
  const total = files.length + dirModes.length;
  let restored = 0;

  const roots = rollbackRoots();
  for (const backupFilePath of files) {
    // The backup preserves absolute paths: backup/<timestamp>/absolute/path/to/file
    // Strip the backup dir prefix to recover the original absolute path
    const originalPath = backupFilePath.slice(backupDir.length);
    try {
      // With a manifest, only what the fix run recorded is restored
      if (manifest && !manifest.entries[originalPath]) {
        console.log(`  ${chalk.yellow('!')} Skipped ${originalPath}: not recorded in this backup's manifest`);
        continue;
      }
      if (dryRun) {
        console.log(`  ${chalk.cyan('[dry-run]')} Would restore ${originalPath}`);
        restored++;
        continue;
      }
      const note = await withFixBoundary({ roots }, () => restoreFile(backupFilePath, originalPath, manifest?.entries[originalPath]));
      if (note) {
        console.log(`  ${chalk.yellow('!')} Skipped ${originalPath}: ${note}; the original is in ${backupFilePath}`);
        continue;
      }
      console.log(`  ${chalk.green('+')} Restored ${originalPath}`);
      restored++;
    } catch (err) {
      console.log(`  ${chalk.red('x')} Failed to restore ${originalPath}: ${(err as Error).message}`);
    }
  }

  // Directory modes a fix changed (NC-002 makes the allowlist dir owner-only),
  // and the modes of files the owner couldn't read (no content copy)
  for (const [dir, entry] of dirModes) {
    try {
      const st = await lstat(dir);
      if (entry.kind === 'dir' ? !st.isDirectory() : !st.isFile()) {
        console.log(`  ${chalk.yellow('!')} Skipped ${dir}: it is no longer a ${entry.kind === 'dir' ? 'directory' : 'regular file'}`);
        continue;
      }
      const moved = await movedSinceBackup(dir, entry, entry.kind === 'dir');
      if (moved) {
        console.log(`  ${chalk.yellow('!')} Skipped ${dir}: ${moved}`);
        continue;
      }
      if (dryRun) {
        console.log(`  ${chalk.cyan('[dry-run]')} Would restore the mode of ${dir}`);
        restored++;
        continue;
      }
      await withFixBoundary({ roots }, () => chmodNoFollow(dir, entry.mode));
      restored++;
    } catch (err) {
      console.log(`  ${chalk.red('x')} Failed to restore the mode of ${dir}: ${(err as Error).message}`);
    }
  }

  // Retire the backup so the next rollback undoes the fix run before it.
  // A partial restore stays pending, to be retried.
  if (dryRun) {
    console.log(`\n${chalk.bold('Dry run:')} ${restored} item(s) would be restored`);
    return;
  }
  if (restored === total && !target.startsWith(RESTORED_PREFIX)) {
    await rename(backupDir, join(backupsDir, `${RESTORED_PREFIX}${target}`));
  }

  console.log(`\n${chalk.bold('Rollback complete:')} ${restored} item(s) restored`);
  // Anything left unrestored (skipped symlink, edited since the fix, copy
  // error) is an incomplete rollback
  if (restored < total) {
    console.log(chalk.yellow(`  ${total - restored} item(s) not restored — the backup stays pending`));
    process.exitCode = 2;
  }
}

/**
 * Whether a backup records no change: every file it holds was left with its
 * content (after = before) and every recorded path still has its recorded
 * mode — restoring it would change nothing. Backups without a manifest (from
 * before 1.3.1) can't tell, so they count as changes.
 */
async function isEmptyBackup(backupDir: string): Promise<boolean> {
  const manifest = await readManifest(backupDir);
  if (!manifest) return (await collectFiles(backupDir).catch(() => [])).length === 0;
  for (const [path, entry] of Object.entries(manifest.entries)) {
    if (entry.kind === 'file' && (entry.after === undefined || entry.after !== entry.before)) return false;
    const st = await lstat(path).catch(() => undefined);
    if (!st || (st.mode & 0o7777) !== entry.mode) return false;
  }
  return true;
}

/**
 * Put one backed-up file back. Returns why it was skipped, if it was:
 * whatever replaced the original (a symlink, a pipe) is not ours to
 * overwrite, and a file edited since the fix keeps the edit — rollback must
 * not silently discard work. A read-only original is made writable for the
 * restore, then given its exact recorded mode (setuid included).
 */
async function restoreFile(backupPath: string, originalPath: string, entry: ManifestEntry | undefined): Promise<string | undefined> {
  const current = await lstat(originalPath).catch(() => undefined);
  if (current && !current.isFile()) {
    return `it is now ${current.isSymbolicLink() ? 'a symlink' : 'not a regular file'}`;
  }
  const moved = entry ? await movedSinceBackup(originalPath, entry, false) : undefined;
  if (moved) return moved;
  const original = await readFile(backupPath);
  const mode = entry?.mode ?? ((await stat(backupPath)).mode & 0o7777);
  let rewrote = false;
  if (current && entry?.after !== undefined && entry.after === entry.before) {
    // The fix run never changed this file's content (it was backed up as a
    // precaution, or only chmod-ed): there is no content to restore, and an
    // edit made since is the user's — keep it and restore just the mode
  } else if (current) {
    const now = await readRegularFile(originalPath).then(sha256, () => undefined);
    if (entry?.after && now !== undefined && now !== entry.after && now !== entry.before) {
      return 'it was changed after the fix';
    }
    if (now === undefined || now !== (entry?.before ?? sha256(original))) {
      await chmodNoFollow(originalPath, 0o600);
      await writeRegularFile(originalPath, original);
      rewrote = true;
    }
  } else {
    await assertCreatable(originalPath);
    await writeFile(originalPath, original, { flag: 'wx', mode: 0o600 });
    rewrote = true;
  }
  // Already at its recorded mode and untouched: nothing to do. (A file the
  // fix refused — a hard link — is in the backup but must not be chmod-ed,
  // or the rollback stays pending forever.)
  const unchanged = !rewrote && current !== undefined && (current.mode & 0o7777) === mode;
  if (process.platform !== 'win32' && !unchanged) await chmodNoFollow(originalPath, mode);
  return undefined;
}

async function collectFiles(dir: string): Promise<string[]> {
  const results: string[] = [];
  const entries = await readdir(dir, { withFileTypes: true, recursive: true });
  for (const entry of entries) {
    if (entry.isFile()) {
      const fullPath = entry.parentPath
        ? join(entry.parentPath, entry.name)
        : join(dir, entry.name);
      results.push(fullPath);
    }
  }
  return results;
}
