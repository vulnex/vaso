import { createHash } from 'node:crypto';
import { appendFile, readFile, writeFile } from 'node:fs/promises';
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
  /** Where the path resolved when backed up (its directory's real path, or
   *  the directory's own) and who owned it: rollback refuses a path that has
   *  since been re-pointed through a symlinked directory or handed to another
   *  owner (1.3.1+; older manifests lack them). */
  realDir?: string;
  uid?: number;
}

export interface BackupManifest {
  version: 1;
  entries: Record<string, ManifestEntry>;
}

export function sha256(data: Buffer): string {
  return createHash('sha256').update(data).digest('hex');
}

export async function readManifest(backupDir: string): Promise<BackupManifest | undefined> {
  let text: string;
  try {
    text = await readFile(join(backupDir, MANIFEST_NAME), 'utf-8');
  } catch {
    return undefined;
  }
  // 1.3.0: one JSON document, rewritten after every backup
  try {
    const m = JSON.parse(text) as BackupManifest;
    if (m && m.version === 1 && m.entries && typeof m.entries === 'object') return m;
  } catch {
    // a journal
  }
  // 1.3.1+: a journal of `{ path, ...fields }` lines, appended as the run goes
  // (O(1) per backed-up file); later lines update earlier ones
  const entries: Record<string, ManifestEntry> = {};
  for (const line of text.split('\n')) {
    if (!line.trim()) continue;
    try {
      const { path, ...fields } = JSON.parse(line) as Partial<ManifestEntry> & { path?: string };
      if (typeof path !== 'string') continue;
      entries[path] = { ...entries[path], ...fields } as ManifestEntry;
    } catch {
      // a line cut short by a crash: the entries before it still count
    }
  }
  return Object.keys(entries).length > 0 ? { version: 1, entries } : undefined;
}

/** Record one manifest entry (or an update to it) — before the change it covers happens. */
export async function appendManifestEntry(backupDir: string, path: string, fields: Partial<ManifestEntry>): Promise<void> {
  await appendFile(join(backupDir, MANIFEST_NAME), `${JSON.stringify({ path, ...fields })}\n`, { mode: 0o600 });
}

export async function writeManifest(backupDir: string, manifest: BackupManifest): Promise<void> {
  await writeFile(join(backupDir, MANIFEST_NAME), JSON.stringify(manifest, null, 2), { mode: 0o600 });
}
