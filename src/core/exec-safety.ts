import { statSync, realpathSync, mkdtempSync, chownSync, rmSync, type Stats } from 'node:fs';
import { delimiter, dirname, isAbsolute, join } from 'node:path';
import { tmpdir } from 'node:os';

/**
 * Rules for running a binary found on the scanned host (agent CLI version
 * queries, `which`). VASO runs them only to read a version string, so:
 *  - an isolated run gets a minimal environment — no CODEX_HOME,
 *    CLAUDE_CONFIG_DIR or other relocation variable that would point the
 *    CLI back at the user's real state directory (`codex --version` writes
 *    there) — and a throwaway HOME;
 *  - as root (`sudo vaso scan --all-users`), nothing another user controls
 *    runs with root's privileges: a binary owned by a user runs as that user,
 *    and a root-owned one only if no other user could have replaced it or a
 *    directory above it; its PATH keeps only root-safe directories.
 * The Go probe applies the same rules on remote hosts (probe/exec_unix.go).
 */

/** Variables a version query keeps; everything else is dropped. */
const KEEP_ENV = ['PATH', 'LANG', 'LC_ALL', 'LC_CTYPE', 'TERM', 'TMPDIR', 'TZ', 'SystemRoot', 'SYSTEMROOT', 'COMSPEC', 'PATHEXT', 'windir', 'USER', 'LOGNAME', 'USERNAME'];

export interface ExecPlan {
  /** Why the command must not run; set when it is refused. */
  refuse?: string;
  env?: NodeJS.ProcessEnv;
  cwd?: string;
  uid?: number;
  gid?: number;
  cleanup: () => void;
}

function isRoot(): boolean {
  return process.getuid?.() === 0;
}

/** Owned by root and not writable by group/other (a sticky dir is fine). */
function rootOwnedSafe(st: Stats): boolean {
  return st.uid === 0 && ((st.mode & 0o022) === 0 || (st.isDirectory() && (st.mode & 0o1000) !== 0));
}

/** No user but root can have put what is at `path` (or any directory above it) in place. */
export function rootSafePath(path: string): boolean {
  try {
    for (let p = realpathSync(path); ; p = dirname(p)) {
      if (!rootOwnedSafe(statSync(p))) return false;
      if (dirname(p) === p) return true;
    }
  } catch {
    return false;
  }
}

/** The file `cmd` resolves to on PATH, the way execFile would find it. */
function resolveOnPath(cmd: string, pathVar: string | undefined): string | undefined {
  if (isAbsolute(cmd) || cmd.includes('/')) return cmd;
  for (const dir of (pathVar ?? '').split(delimiter)) {
    if (!dir) continue;
    try {
      const candidate = join(dir, cmd);
      const st = statSync(candidate);
      if (st.isFile() && (st.mode & 0o111) !== 0) return candidate;
    } catch {
      // not here
    }
  }
  return undefined;
}

export function planExec(cmd: string, options: { isolateHome?: boolean; cwd?: string; path?: string } | undefined): ExecPlan {
  let env: NodeJS.ProcessEnv | undefined;
  let cwd = options?.cwd;
  let cleanup = () => {};
  let uid: number | undefined;
  let gid: number | undefined;

  const pathVar = options?.path ?? process.env.PATH;
  if (options?.path !== undefined) env = { ...process.env, PATH: options.path };

  if (isRoot()) {
    const resolved = resolveOnPath(cmd, pathVar);
    if (!resolved) return { refuse: `${cmd} not found`, cleanup };
    let st: Stats;
    try {
      st = statSync(realpathSync(resolved));
    } catch {
      return { refuse: `${cmd} not found`, cleanup };
    }
    if (st.uid !== 0) {
      uid = st.uid;
      gid = st.gid;
    } else if (!rootSafePath(resolved)) {
      return { refuse: `${resolved} is writable by a non-root user; not run as root`, cleanup };
    }
    const safePath = (pathVar ?? '').split(delimiter).filter(d => d && rootSafePath(d)).join(delimiter);
    env = { ...process.env, PATH: uid === undefined ? safePath : pathVar };
  }

  if (options?.isolateHome) {
    let home: string;
    try {
      home = mkdtempSync(join(tmpdir(), 'vaso-exec-'));
    } catch {
      // TMPDIR unusable: fall back to the system default rather than skipping
      // the query (or running it against the real HOME)
      try {
        home = mkdtempSync(join(process.platform === 'win32' ? tmpdir() : '/tmp', 'vaso-exec-'));
      } catch (err) {
        return { refuse: `no temporary directory for an isolated run: ${(err as Error).message}`, cleanup };
      }
    }
    if (uid !== undefined) {
      try {
        chownSync(home, uid, gid ?? -1);
      } catch {
        // stays root-owned: the CLI just can't write its throwaway state
      }
    }
    const base = env ?? process.env;
    env = Object.fromEntries(KEEP_ENV.filter(k => base[k] !== undefined).map(k => [k, base[k]]));
    Object.assign(env, {
      HOME: home,
      USERPROFILE: home,
      APPDATA: join(home, 'AppData', 'Roaming'),
      LOCALAPPDATA: join(home, 'AppData', 'Local'),
      XDG_CONFIG_HOME: join(home, '.config'),
      XDG_DATA_HOME: join(home, '.local', 'share'),
      XDG_CACHE_HOME: join(home, '.cache'),
      XDG_STATE_HOME: join(home, '.local', 'state'),
    });
    cwd = options.cwd ?? home;
    cleanup = () => rmSync(home, { recursive: true, force: true });
  }
  return { env, cwd, uid, gid, cleanup };
}
