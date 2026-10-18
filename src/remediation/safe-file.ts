import { open, lstat, chmod, realpath } from 'node:fs/promises';
import { constants } from 'node:fs';
import { dirname, isAbsolute, sep } from 'node:path';
import { AsyncLocalStorage } from 'node:async_hooks';

/**
 * File I/O for `vaso fix` and `--rollback`. Fixes write into paths taken from
 * the scanned host, which the user or another local user controls:
 *  - a symlinked config would let a fix write (or chmod) the link's target —
 *    any file the scanning user can write, root's when run as root;
 *  - a FIFO or device in place of a config blocks a plain read forever.
 * Every open here refuses symlinks (O_NOFOLLOW, checked by the kernel, so a
 * swap between check and use doesn't get around it), never blocks
 * (O_NONBLOCK), and confirms on the open handle that the target is a regular
 * file before reading or writing.
 */

const NOFOLLOW = constants.O_NOFOLLOW ?? 0;

/**
 * Called with a path just before it is written or chmod-ed — the fix engine
 * backs it up there, so every file and directory a fix changes is in the
 * backup, not only the ones the finding names (NC-002 chmods its config
 * directory; a list made up front missed it and rollback left it 700).
 */
const changeRecorder = new AsyncLocalStorage<(path: string) => Promise<void>>();

/** Run `fn` with `record` called before each change this module makes. */
export function withChangeRecorder<T>(record: (path: string) => Promise<void>, fn: () => Promise<T>): Promise<T> {
  return changeRecorder.run(record, fn);
}

async function beforeChange(path: string): Promise<void> {
  await changeRecorder.getStore()?.(path);
}
const NONBLOCK = constants.O_NONBLOCK ?? 0;

/**
 * Where a fix may write: the home of the user whose installation is being
 * fixed, and the installation's own directory. A path whose directory
 * resolves elsewhere — `~/.config` made a symlink to `/etc` — is refused, and
 * as root the file must belong to that home's owner, so neither a symlinked
 * directory (swapped after the check or not) nor a hard link to a root-owned
 * file turns a fix into a write to someone else's file. A symlink that stays
 * inside the home (a dotfiles repo) is fine.
 */
export interface FixBoundary {
  roots: string[];
  /** Whose files these are: the owner of the home the installation lives in
   *  (or of the install dir, for a system-wide one). Enforced as root, where
   *  the roots themselves can be symlinks a user points anywhere. */
  ownerUid?: number;
}

const boundary = new AsyncLocalStorage<FixBoundary>();

/** Run `fn` (a fix) with writes confined to `b`. */
export function withFixBoundary<T>(b: FixBoundary, fn: () => Promise<T>): Promise<T> {
  return boundary.run(b, fn);
}

function within(path: string, root: string): boolean {
  return path === root || path.startsWith(root.endsWith(sep) ? root : root + sep);
}

/**
 * Refuse a target vaso must not change: a file with more than one hard link
 * (the change would reach every name, wherever it lives), or, inside a fix
 * boundary, one outside it or (as root) owned by someone else. `st` comes
 * from the open handle where there is one.
 */
async function guard(path: string, st: { isFile(): boolean; nlink: number; uid: number }, isDir = false): Promise<void> {
  if (st.isFile() && st.nlink > 1) {
    throw new UnsafeTargetError(path, `has ${st.nlink} hard links (a change would reach the other names too)`);
  }
  const b = boundary.getStore();
  if (!b) return;
  const real = await realpath(isDir ? path : dirname(path)).catch(() => undefined);
  if (!real) throw new UnsafeTargetError(path, 'is in a directory that can no longer be resolved');
  if (process.getuid?.() === 0 && b.ownerUid !== undefined && st.uid !== b.ownerUid) {
    throw new UnsafeTargetError(path, `is owned by uid ${st.uid}, not by the installation's owner (uid ${b.ownerUid})`);
  }
  for (const root of b.roots) {
    const realRoot = await realpath(root).catch(() => undefined);
    if (realRoot && within(real, realRoot)) return;
  }
  throw new UnsafeTargetError(path, `resolves into ${real}, outside ${b.roots.join(' and ')} (where rollback can restore it)`);
}

/** The boundary check for a path about to be created (no handle to stat yet). */
export async function assertCreatable(path: string): Promise<void> {
  requireAbsolute(path);
  await guard(path, { isFile: () => false, nlink: 1, uid: process.getuid?.() ?? -1 });
}

export class UnsafeTargetError extends Error {
  constructor(readonly path: string, readonly reason: string) {
    super(`${path} ${reason} — vaso fix won't write it`);
  }
}

/** Only absolute paths can be backed up and rolled back; a relative one would land wherever vaso runs. */
function requireAbsolute(path: string): void {
  if (!isAbsolute(path)) throw new UnsafeTargetError(path, 'is not an absolute path (it could not be backed up)');
}

function refuse(path: string, err: unknown): never {
  if ((err as NodeJS.ErrnoException).code === 'ELOOP') throw new UnsafeTargetError(path, 'is a symlink');
  throw err;
}

/** Read a regular file (no symlink, no FIFO/device). */
export async function readRegularFile(path: string): Promise<Buffer> {
  const handle = await open(path, constants.O_RDONLY | NOFOLLOW | NONBLOCK).catch(err => refuse(path, err));
  try {
    const st = await handle.stat();
    if (!st.isFile()) throw new UnsafeTargetError(path, 'is not a regular file');
    return await handle.readFile();
  } finally {
    await handle.close();
  }
}

/** Replace the content of an existing regular file in place (mode and owner kept). */
export async function writeRegularFile(path: string, data: string | Buffer): Promise<void> {
  requireAbsolute(path);
  const handle = await open(path, constants.O_WRONLY | NOFOLLOW | NONBLOCK).catch(err => refuse(path, err));
  try {
    const st = await handle.stat();
    if (!st.isFile()) throw new UnsafeTargetError(path, 'is not a regular file');
    await guard(path, st);
    // backed up only once it is certain to change
    await beforeChange(path);
    await handle.truncate(0);
    await handle.write(typeof data === 'string' ? Buffer.from(data, 'utf-8') : data, 0, undefined, 0);
  } finally {
    await handle.close();
  }
}

/**
 * chmod a regular file or a directory, never through a symlink. A file is
 * chmod-ed on its open handle; one the user can't even open (mode 000) falls
 * back to a path chmod after an lstat check.
 */
export async function chmodNoFollow(path: string, mode: number): Promise<void> {
  requireAbsolute(path);
  const st = await lstat(path);
  if (st.isSymbolicLink()) throw new UnsafeTargetError(path, 'is a symlink');
  if (!st.isFile() && !st.isDirectory()) throw new UnsafeTargetError(path, 'is not a regular file');
  if (st.isDirectory()) {
    await guard(path, st, true);
    await beforeChange(path);
    await chmod(path, mode);
    return;
  }
  const handle = await open(path, constants.O_RDONLY | NOFOLLOW | NONBLOCK).catch(() => undefined);
  if (!handle) {
    await guard(path, st);
    await beforeChange(path);
    await chmod(path, mode);
    return;
  }
  try {
    const opened = await handle.stat();
    if (!opened.isFile()) throw new UnsafeTargetError(path, 'is not a regular file');
    await guard(path, opened);
    await beforeChange(path);
    await handle.chmod(mode);
  } finally {
    await handle.close();
  }
}

/** Mode bits (incl. setuid/setgid/sticky) and owner of a regular file or directory; refuses anything else. */
export async function regularMode(path: string): Promise<{ mode: number; dir: boolean; uid: number }> {
  const st = await lstat(path);
  if (st.isSymbolicLink()) throw new UnsafeTargetError(path, 'is a symlink');
  if (!st.isFile() && !st.isDirectory()) throw new UnsafeTargetError(path, 'is not a regular file');
  return { mode: st.mode & 0o7777, dir: st.isDirectory(), uid: st.uid };
}

/** The real path a target resolves through: its own for a directory, its parent's for a file. */
export async function resolvedDir(path: string, isDir: boolean): Promise<string | undefined> {
  return realpath(isDir ? path : dirname(path)).catch(() => undefined);
}

/**
 * Why rollback must not touch `path` any more, if it must not: its directory
 * now resolves somewhere else than when it was backed up (a component was
 * swapped for a symlink), or — as root — it belongs to someone else now.
 */
export async function movedSinceBackup(path: string, entry: { realDir?: string; uid?: number }, isDir: boolean): Promise<string | undefined> {
  if (entry.realDir !== undefined && (await resolvedDir(path, isDir)) !== entry.realDir) {
    return 'its directory now resolves somewhere else than when it was backed up';
  }
  if (entry.uid !== undefined && process.getuid?.() === 0) {
    const st = await lstat(path).catch(() => undefined);
    if (st && st.uid !== entry.uid) return `it is now owned by uid ${st.uid}, not ${entry.uid}`;
  }
  return undefined;
}
