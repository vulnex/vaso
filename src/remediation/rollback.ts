import { readdir, copyFile, stat, lstat, chmod, rename } from 'node:fs/promises';
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
  const files = await collectFiles(backupDir);
  let restored = 0;

  for (const backupFilePath of files) {
    // The backup preserves absolute paths: backup/<timestamp>/absolute/path/to/file
    // Strip the backup dir prefix to recover the original absolute path
    const originalPath = backupFilePath.slice(backupDir.length);
    try {
      // Never write through a link or onto a non-file: whatever replaced the
      // original since the fix (a symlink to another file, a directory) is
      // not ours to overwrite — and copyFile/chmod would follow a symlink.
      const current = await lstat(originalPath).catch(() => undefined);
      if (current && !current.isFile()) {
        console.log(`  ${chalk.red('x')} Skipped ${originalPath}: it is now ${current.isSymbolicLink() ? 'a symlink' : 'not a regular file'}; restore it by hand from ${backupFilePath}`);
        continue;
      }
      await copyFile(backupFilePath, originalPath);
      // The backup copy kept the original permissions; restore them too
      // (permission fixes such as chmod 600 are part of the rollback).
      if (process.platform !== 'win32') {
        await chmod(originalPath, (await stat(backupFilePath)).mode & 0o7777);
      }
      console.log(`  ${chalk.green('+')} Restored ${originalPath}`);
      restored++;
    } catch (err) {
      console.log(`  ${chalk.red('x')} Failed to restore ${originalPath}: ${(err as Error).message}`);
    }
  }

  // Retire the backup so the next rollback undoes the fix run before it.
  // A partial restore stays pending, to be retried.
  if (restored === files.length && !target.startsWith(RESTORED_PREFIX)) {
    await rename(backupDir, join(backupsDir, `${RESTORED_PREFIX}${target}`));
  }

  console.log(`\n${chalk.bold('Rollback complete:')} ${restored} file(s) restored`);
  // A file left unrestored (skipped symlink, copy error) is an incomplete rollback
  if (restored < files.length) {
    console.log(chalk.yellow(`  ${files.length - restored} file(s) not restored — the backup stays pending`));
    process.exitCode = 2;
  }
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
