import { open, lstat, chmod } from 'node:fs/promises';
import { constants } from 'node:fs';

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
const NONBLOCK = constants.O_NONBLOCK ?? 0;

export class UnsafeTargetError extends Error {
  constructor(readonly path: string, readonly reason: string) {
    super(`${path} ${reason} — vaso fix won't write it`);
  }
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
  const handle = await open(path, constants.O_WRONLY | NOFOLLOW | NONBLOCK).catch(err => refuse(path, err));
  try {
    const st = await handle.stat();
    if (!st.isFile()) throw new UnsafeTargetError(path, 'is not a regular file');
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
  const st = await lstat(path);
  if (st.isSymbolicLink()) throw new UnsafeTargetError(path, 'is a symlink');
  if (st.isDirectory()) {
    await chmod(path, mode);
    return;
  }
  if (!st.isFile()) throw new UnsafeTargetError(path, 'is not a regular file');
  const handle = await open(path, constants.O_RDONLY | NOFOLLOW | NONBLOCK).catch(() => undefined);
  if (!handle) {
    await chmod(path, mode);
    return;
  }
  try {
    if (!(await handle.stat()).isFile()) throw new UnsafeTargetError(path, 'is not a regular file');
    await handle.chmod(mode);
  } finally {
    await handle.close();
  }
}

/** Mode bits (incl. setuid/setgid/sticky) of a regular file or directory; refuses anything else. */
export async function regularMode(path: string): Promise<{ mode: number; dir: boolean }> {
  const st = await lstat(path);
  if (st.isSymbolicLink()) throw new UnsafeTargetError(path, 'is a symlink');
  if (!st.isFile() && !st.isDirectory()) throw new UnsafeTargetError(path, 'is not a regular file');
  return { mode: st.mode & 0o7777, dir: st.isDirectory() };
}
