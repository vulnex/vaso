import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

/**
 * What a fix run backed up, next to the copies in ~/.vaso/backups/<ts>/:
 * each file's full mode (setuid/setgid included — a copy can't carry them)
 * and content hash before the fix and after it, and the mode of each
 * directory a fix may chmod. Rollback uses it to restore modes exactly and to
 * leave alone a file edited since the fix rather than silently discarding the
 * edit. Backups from before 1.3.1 have no manifest (rollback copies back).
 */
export const MANIFEST_NAME = '.vaso-manifest.json';

export interface ManifestEntry {
  /** `mode`: a file the owner can't read (mode 000) — only its mode is
   *  recorded; a fix can only have chmod-ed it. */
  kind: 'file' | 'dir' | 'mode';
  mode: number;
  /** sha256 of the content before the fix (files). */
  before?: string;
  /** sha256 after the run's fixes (files); absent while a fix is running. */
  after?: string;
}

export interface BackupManifest {
  version: 1;
  entries: Record<string, ManifestEntry>;
}

export function sha256(data: Buffer): string {
  return createHash('sha256').update(data).digest('hex');
}

export async function readManifest(backupDir: string): Promise<BackupManifest | undefined> {
  try {
    const m = JSON.parse(await readFile(join(backupDir, MANIFEST_NAME), 'utf-8')) as BackupManifest;
    return m && m.version === 1 && m.entries && typeof m.entries === 'object' ? m : undefined;
  } catch {
    return undefined;
  }
}

export async function writeManifest(backupDir: string, manifest: BackupManifest): Promise<void> {
  await writeFile(join(backupDir, MANIFEST_NAME), JSON.stringify(manifest, null, 2), { mode: 0o600 });
}
