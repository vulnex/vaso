/**
 * Whether a file whose content steers VASO — ~/.vaso/trusted-projects, a rule
 * in ~/.vaso/rules, a user plugin in ~/.vaso/plugins — can be relied on:
 * nobody but the person running VASO (or root) can change or replace it.
 */
import { dirname } from 'node:path';
import { lstat, realpath, stat } from 'node:fs/promises';
import type { FSProvider } from './fs-provider.js';

/**
 * Write access beyond the owner: others' write bit, or the group's — unless
 * the group is the owner's private group (umask 002 distributions), which
 * reaches nobody else.
 */
function othersCanWrite(st: { mode: number; uid: number; gid: number }, privateGroups: ReadonlyMap<number, number>): boolean {
  return (st.mode & 0o002) !== 0 || ((st.mode & 0o020) !== 0 && privateGroups.get(st.gid) !== st.uid);
}

/** The user's own uid, or root's: a root-owned file or directory is as safe as one's own. */
function ownedBySelf(owner: number, uid: number | undefined): boolean {
  return uid === undefined || owner === uid || owner === 0;
}

async function privateGroupsOf(fs: FSProvider): Promise<ReadonlyMap<number, number>> {
  return (await fs.privateGroups?.().catch(() => undefined)) ?? new Map<number, number>();
}

/**
 * Why a file whose content steers VASO can't be relied on, undefined when it
 * can: someone else could change it, or replace it through its directory.
 * The file — or a symlink's target — must be the user's own and only
 * owner-writable; the directory holding it and the directory holding the
 * link's target must be the user's own and owner-writable (a sticky
 * directory is enough for the target's: others can't rename or replace a
 * file they don't own there). `outcome` ends the sentence (`ignored`,
 * `not loaded`). Throws when the file can't be stat'd.
 */
export async function ownedFileProblem(file: string, outcome: string, fs: FSProvider): Promise<string | undefined> {
  if (process.platform === 'win32') return undefined;
  const uid = process.getuid?.();
  const groups = await privateGroupsOf(fs);
  const st = await stat(file);
  const link = await lstat(file);
  const dir = await stat(dirname(file));
  if (othersCanWrite(st, groups)) return `${file} is writable by group or others — ${outcome} (chmod 600 it to use it)`;
  if (!ownedBySelf(st.uid, uid) || !ownedBySelf(link.uid, uid)) return `${file} is not owned by you — ${outcome}`;
  if (othersCanWrite(dir, groups)) return `${dirname(file)} is writable by group or others — ${file} ${outcome} (chmod 700 it to use it)`;
  if (!ownedBySelf(dir.uid, uid)) return `${dirname(file)} is not owned by you — ${file} ${outcome}`;
  let real: string;
  try {
    real = await realpath(file);
  } catch {
    return undefined;
  }
  if (dirname(real) !== (await realpath(dirname(file)).catch(() => dirname(file)))) {
    const targetDir = await stat(dirname(real));
    if (othersCanWrite(targetDir, groups) && (targetDir.mode & 0o1000) === 0) {
      return `${file} links to ${real}, in a directory group or others can write (they could replace it) — ${outcome}`;
    }
  }
  return undefined;
}

/**
 * Why a directory of files that steer VASO (~/.vaso/rules, ~/.vaso/plugins)
 * can't be relied on: one of `dirs` (it, and ~/.vaso holding it) is writable
 * by others or not the user's — anyone could add or swap an entry. A
 * directory that doesn't exist is no problem (nothing to load).
 * `outcome` ends the sentence; `them` names the entries in the chmod hint.
 */
export async function ownedDirsProblem(dirs: readonly string[], outcome: string, them: string, fs: FSProvider): Promise<string | undefined> {
  if (process.platform === 'win32') return undefined;
  const uid = process.getuid?.();
  const groups = await privateGroupsOf(fs);
  for (const [i, d] of dirs.entries()) {
    let st: Awaited<ReturnType<typeof stat>>;
    try {
      st = await stat(d);
    } catch {
      return undefined;
    }
    // a sticky directory above the first (root's /tmp holding a mkdtemp
    // dir) keeps others from renaming the user's own directory in it
    const sticky = i > 0 && (st.mode & 0o1000) !== 0;
    if (othersCanWrite(st, groups) && !sticky) return `${d} is writable by group or others — ${outcome} (chmod 700 it to use ${them})`;
    if (!ownedBySelf(st.uid, uid)) return `${d} is not owned by you — ${outcome}`;
  }
  return undefined;
}
