import { readdir, copyFile } from 'node:fs/promises';
import { join } from 'node:path';
import { homedir } from 'node:os';
import chalk from 'chalk';
import { pathExists } from '../core/utils.js';

/**
 * Restore files from a VASO backup directory.
 * If no timestamp is given, uses the most recent backup.
 */
export async function rollback(timestamp?: string): Promise<void> {
  const backupsDir = join(homedir(), '.vaso', 'backups');

  if (!await pathExists(backupsDir)) {
    console.log(chalk.yellow('No backups found at ~/.vaso/backups/'));
    return;
  }

  const entries = await readdir(backupsDir, { withFileTypes: true });
  const dirs = entries.filter(e => e.isDirectory()).map(e => e.name).sort();

  if (dirs.length === 0) {
    console.log(chalk.yellow('No backup directories found.'));
    return;
  }

  const target = timestamp
    ? dirs.find(d => d.includes(timestamp))
    : dirs[dirs.length - 1];

  if (!target) {
    console.log(chalk.red(`No backup matching "${timestamp}" found.`));
    console.log(`Available backups: ${dirs.join(', ')}`);
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
      await copyFile(backupFilePath, originalPath);
      console.log(`  ${chalk.green('+')} Restored ${originalPath}`);
      restored++;
    } catch (err) {
      console.log(`  ${chalk.red('x')} Failed to restore ${originalPath}: ${(err as Error).message}`);
    }
  }

  console.log(`\n${chalk.bold('Rollback complete:')} ${restored} file(s) restored`);
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
