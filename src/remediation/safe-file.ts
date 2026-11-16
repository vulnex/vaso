import { open, lstat, chmod, realpath, rename, unlink } from 'node:fs/promises';
import { constants } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { basename, dirname, isAbsolute, join, sep } from 'node:path';
import { AsyncLocalStorage } from 'node:async_hooks';
import { execFile } from 'node:child_process';
import { classifySensitivePath } from '../analyzers/sensitive-paths.js';

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

/** Whether `path` is `root` or inside it (also what the scan judges refusals by — fix-refusal.ts). */
export function withinRoot(path: string, root: string): boolean {
  return path === root || path.startsWith(root.endsWith(sep) ? root : root + sep);
}

/**
 * The sensitive location (a credential store, a shell startup file, /etc)
 * that `real` — where `written` really is — lies in and `written` doesn't
 * name: a link above it leads there (`~/.copilot → ~/.aws/cop`). Undefined
 * when there is none, or the written path names it already (a fix of
 * ~/.ssh/<key>'s mode by its own path). vaso fix never writes into one
 * through a link (also what the scan judges refusals by — fix-refusal.ts).
 */
export function sinkReachedThroughLink(written: string, real: string): string | undefined {
  const named = new Set(classifySensitivePath(written));
  return classifySensitivePath(real).find(label => !named.has(label));
}

/** Run `fn` (a fix) with writes confined to `b`. */
export function withFixBoundary<T>(b: FixBoundary, fn: () => Promise<T>): Promise<T> {
  return boundary.run(b, fn);
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
  const sink = sinkReachedThroughLink(path, isDir ? real : join(real, basename(path)));
  if (sink) throw new UnsafeTargetError(path, `is reached through a symlink into ${sink}`);
  if (process.getuid?.() === 0 && b.ownerUid !== undefined && st.uid !== b.ownerUid) {
    throw new UnsafeTargetError(path, `is owned by uid ${st.uid}, not by the installation's owner (uid ${b.ownerUid})`);
  }
  for (const root of b.roots) {
    const realRoot = await realpath(root).catch(() => undefined);
    if (realRoot && withinRoot(real, realRoot)) return;
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

/**
 * Replace the content of an existing regular file, keeping its mode and owner.
 * The new content goes to a temporary file in the same directory that is then
 * renamed over the original, so a reader (the agent itself) never sees a
 * truncated or half-written config. The original is still opened for writing
 * first: a file the user made read-only stays refused, as do symlinks and
 * anything that is not a regular file. A directory vaso can't create files in,
 * and a file whose ACL, extended attributes or flags a new inode would lose
 * (or whose directory would hand the new inode an inherited ACL), fall back to
 * rewriting the file in place — see `renameKeepsMetadata`.
 */
export async function writeRegularFile(path: string, data: string | Buffer): Promise<void> {
  requireAbsolute(path);
  const bytes = typeof data === 'string' ? Buffer.from(data, 'utf-8') : data;
  const handle = await open(path, constants.O_WRONLY | NOFOLLOW | NONBLOCK).catch(err => refuse(path, err));
  try {
    const st = await handle.stat();
    if (!st.isFile()) throw new UnsafeTargetError(path, 'is not a regular file');
    await guard(path, st);
    // backed up only once it is certain to change
    await beforeChange(path);
    if (await replaceByRename(path, bytes, st)) return;
    await handle.truncate(0);
    await handle.write(bytes, 0, undefined, 0);
  } finally {
    await handle.close();
  }
}

/**
 * Write `bytes` to a sibling temporary file with the original's mode (and
 * owner, where it can be set) and rename it over `path`. Returns false when
 * the directory doesn't allow creating it, so the caller rewrites in place.
 *
 * Only for the user's own files, and not as root: the temporary file and the rename resolve the directory path
 * again, and a user who swaps a directory for a symlink in between could
 * point a root write elsewhere — root keeps writing through the checked handle.
 */
async function replaceByRename(path: string, bytes: Buffer, st: { mode: number; uid: number; gid: number }): Promise<boolean> {
  // A file someone else owns would change owner by the rename: rewrite in place
  const uid = process.getuid?.();
  if (uid === undefined || uid === 0 || st.uid !== uid) return false;
  if (!(await renameKeepsMetadata(path))) return false;
  const tmp = join(dirname(path), `.${basename(path)}.vaso-${process.pid}-${randomBytes(4).toString('hex')}.tmp`);
  let tmpHandle;
  try {
    tmpHandle = await open(tmp, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | NOFOLLOW, 0o600);
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === 'EACCES' || code === 'EPERM' || code === 'EROFS') return false;
    throw err;
  }
  let renamed = false;
  try {
    try {
      await tmpHandle.write(bytes, 0, undefined, 0);
      // group first (best effort): chown clears setgid, which the chmod restores
      await tmpHandle.chown(-1, st.gid).catch(() => undefined);
      await tmpHandle.chmod(st.mode & 0o7777);
      await tmpHandle.sync();
    } finally {
      await tmpHandle.close();
    }
    await rename(tmp, path);
    renamed = true;
    return true;
  } finally {
    if (!renamed) await unlink(tmp).catch(() => undefined);
  }
}

/**
 * Whether a renamed-in replacement of `path` would carry everything the
 * original has. A new inode gets only the mode and group vaso copies: an ACL,
 * extended attributes (Finder tags, anything an app stores) and file flags
 * (`hidden`) on the original would be lost, and an inheritable ACL on the
 * directory (macOS `file_inherit`, Linux default ACL) would be added — possibly
 * granting another account read access to a file that had none. Node has no
 * API for any of these, so it asks `ls` (macOS) or `getfattr`/`lsattr`
 * (Linux). Anything it can't confirm — another platform, a tool missing or
 * failing, output it doesn't recognise — answers false: in place is always
 * the safe way to write.
 */
export async function renameKeepsMetadata(path: string): Promise<boolean> {
  try {
    // the replacement is created in the real directory: through a symlinked
    // one, `ls -d` would describe the link, which carries no ACL
    const parent = await realpath(dirname(path));
    if (process.platform === 'darwin') {
      const [file, dir] = await Promise.all([run('/bin/ls', ['-lnde@O', '--', path]), run('/bin/ls', ['-lnde@O', '--', parent])]);
      return darwinPlain(file, false) && darwinPlain(dir, true);
    }
    if (process.platform === 'linux') {
      const [fileAttrs, dirAttrs, flags] = await Promise.all([
        run('getfattr', ['--absolute-names', '-m', '-', '--', path]),
        run('getfattr', ['--absolute-names', '-m', '-', '--', parent]),
        run('lsattr', ['-d', '--', path]),
      ]);
      return linuxXattrNames(fileAttrs).length === 0
        && !linuxXattrNames(dirAttrs).includes('system.posix_acl_default')
        && linuxFlagsPlain(flags);
    }
  } catch {
    /* tool missing or failed: in place */
  }
  return false;
}

function run(cmd: string, args: string[]): Promise<string> {
  return new Promise((resolve, reject) => {
    execFile(cmd, args, { timeout: 5000, maxBuffer: 1 << 20, env: { ...process.env, LC_ALL: 'C' } }, (err, stdout) => {
      if (err) reject(err);
      else resolve(stdout);
    });
  });
}

/** Set by the kernel on files a tracked process creates — the replacement gets its own. */
const SYSTEM_XATTRS = new Set(['com.apple.provenance']);

/**
 * `ls -lnde@O` of one entry: the long line (flags in the fifth column),
 * then a tab-led line per extended attribute and a ` N: ` line per ACL entry.
 * For the file: no flags, no ACL, no attribute but the kernel's provenance tag.
 * For the directory: no ACL entry a new file would inherit.
 */
export function darwinPlain(out: string, isDir: boolean): boolean {
  const lines = out.split('\n').filter(l => l !== '');
  const head = lines.shift()?.split(/\s+/);
  if (!head || head.length < 6 || !/^[-dlbcps][-rwxsStT]{9}[@+]?$/.test(head[0])) return false;
  if (!isDir && head[4] !== '-') return false;
  for (const line of lines) {
    const acl = /^\s*\d+: (.*)$/.exec(line);
    if (acl) {
      if (!isDir || /\bfile_inherit\b/.test(acl[1])) return false;
      continue;
    }
    // `\t<name>\t<size>`: a name holding a tab (`com.apple.provenance\tz`)
    // doesn't fit, so it is not mistaken for the kernel's tag
    const xattr = /^\t([^\t]+)\t *\d+ *$/.exec(line);
    if (xattr) {
      if (!isDir && !SYSTEM_XATTRS.has(xattr[1])) return false;
      continue;
    }
    return false; // a line it doesn't recognise (a newline in the name, a new ls format)
  }
  return true;
}

/** Attribute names `getfattr -m -` lists (incl. `system.posix_acl_*` and `security.*`). */
export function linuxXattrNames(out: string): string[] {
  return out.split('\n').map(l => l.trim()).filter(l => l !== '' && !l.startsWith('# file:'));
}

/** `lsattr -d`: only filesystem-internal flags (extents, inline data, indexed dir) may be set. */
export function linuxFlagsPlain(out: string): boolean {
  const flags = out.trim().split(/\s+/)[0] ?? '';
  return /^[-eNI]+$/.test(flags);
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
