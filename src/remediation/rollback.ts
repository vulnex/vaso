import { readdir, readFile, writeFile, stat, lstat, rename } from 'node:fs/promises';
import { readRegularFile, writeRegularFile, chmodNoFollow } from './safe-file.js';
import { MANIFEST_NAME, readManifest, sha256, type ManifestEntry } from './backup-manifest.js';
import { join } from 'node:path';
import { homedir } from 'node:os';
import chalk from 'chalk';
import { pathExists } from '../core/utils.js';

/** A backup already restored: kept, but no longer "the last fix run". */
const RESTORED_PREFIX = 'restored-';

/**
 * Restore files from a VASO backup directory.
 * If no timestamp is given, uses the most recent backup not yet restored —
 * so repeated rollbacks undo fix runs one at a time, newest first.
 */
export async function rollback(timestamp?: string): Promise<void> {
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

  const exact = timestamp ? dirs.filter(d => d === timestamp || d === `${RESTORED_PREFIX}${timestamp}`) : [];
  const matches = !timestamp ? [pending[pending.length - 1]]
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
  console.log(chalk.cyan(`Restoring from backup: ${target}`));

  // Collect all files recursively from the backup directory
  const manifest = await readManifest(backupDir);
  const files = (await collectFiles(backupDir)).filter(f => f !== join(backupDir, MANIFEST_NAME));
  const dirModes = Object.entries(manifest?.entries ?? {}).filter(([, e]) => e.kind === 'dir');
  const total = files.length + dirModes.length;
  let restored = 0;

  for (const backupFilePath of files) {
    // The backup preserves absolute paths: backup/<timestamp>/absolute/path/to/file
    // Strip the backup dir prefix to recover the original absolute path
    const originalPath = backupFilePath.slice(backupDir.length);
    try {
      const note = await restoreFile(backupFilePath, originalPath, manifest?.entries[originalPath]);
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

  // Directory modes a fix changed (NC-002 makes the allowlist dir owner-only)
  for (const [dir, entry] of dirModes) {
    try {
      const st = await lstat(dir);
      if (!st.isDirectory()) {
        console.log(`  ${chalk.yellow('!')} Skipped ${dir}: it is no longer a directory`);
        continue;
      }
      await chmodNoFollow(dir, entry.mode);
      restored++;
    } catch (err) {
      console.log(`  ${chalk.red('x')} Failed to restore the mode of ${dir}: ${(err as Error).message}`);
    }
  }

  // Retire the backup so the next rollback undoes the fix run before it.
  // A partial restore stays pending, to be retried.
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
  const original = await readFile(backupPath);
  const mode = entry?.mode ?? ((await stat(backupPath)).mode & 0o7777);
  if (current) {
    const now = await readRegularFile(originalPath).then(sha256, () => undefined);
    if (entry?.after && now !== undefined && now !== entry.after && now !== entry.before) {
      return 'it was changed after the fix';
    }
    if (now === undefined || now !== (entry?.before ?? sha256(original))) {
      await chmodNoFollow(originalPath, 0o600);
      await writeRegularFile(originalPath, original);
    }
  } else {
    await writeFile(originalPath, original, { flag: 'wx', mode: 0o600 });
  }
  if (process.platform !== 'win32') await chmodNoFollow(originalPath, mode);
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
