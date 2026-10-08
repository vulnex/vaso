import { access as fsAccess, readdir, readFile, stat, realpath, readlink } from 'node:fs/promises';
import { execFileSync, execFile } from 'node:child_process';
import { constants as fsConstants, mkdtempSync, rmSync, type Dirent } from 'node:fs';
import { join } from 'node:path';
import { homedir as osHomedir, hostname as osHostname, tmpdir } from 'node:os';
import { promisify } from 'node:util';
import type { FSProvider, DirentInfo, ExecResult, ExecOptions, PermissionQuery } from './fs-provider.js';
import type { Platform } from './types.js';
import { posixPermissionFacts } from './permissions.js';
import { parsePrivateGroups } from './private-groups.js';

const execFileAsync = promisify(execFile);

/** Throwaway HOME for `isolateHome` execs; `cleanup` removes it. */
function isolatedEnv(options?: ExecOptions): { env?: NodeJS.ProcessEnv; cwd?: string; cleanup: () => void } {
  if (!options?.isolateHome) return { cwd: options?.cwd, cleanup: () => {} };
  const home = mkdtempSync(join(tmpdir(), 'vaso-exec-'));
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    HOME: home,
    USERPROFILE: home,
    APPDATA: join(home, 'AppData', 'Roaming'),
    LOCALAPPDATA: join(home, 'AppData', 'Local'),
    XDG_CONFIG_HOME: join(home, '.config'),
    XDG_DATA_HOME: join(home, '.local', 'share'),
    XDG_CACHE_HOME: join(home, '.cache'),
    XDG_STATE_HOME: join(home, '.local', 'state'),
  };
  return { env, cwd: options.cwd ?? home, cleanup: () => rmSync(home, { recursive: true, force: true }) };
}

/**
 * Reads a regular file only. A FIFO where a config is expected would block
 * the scan forever and a device such as /dev/zero never ends; both can be
 * planted in a scanned directory. stat() follows symlinks, so a link to a
 * device is caught too; O_NONBLOCK keeps a FIFO swapped in after the check
 * from blocking (the read then sees end-of-file).
 */
async function readRegularFile(path: string): Promise<Buffer>;
async function readRegularFile(path: string, encoding: 'utf-8'): Promise<string>;
async function readRegularFile(path: string, encoding?: 'utf-8'): Promise<Buffer | string> {
  let info: Awaited<ReturnType<typeof stat>> | undefined;
  try { info = await stat(path); } catch { /* readFile reports a missing/unreadable path */ }
  if (info?.isDirectory?.()) {
    throw Object.assign(new Error(`EISDIR: illegal operation on a directory, read '${path}'`), { code: 'EISDIR' });
  }
  if (info?.isFile && !info.isFile()) {
    throw Object.assign(new Error(`EINVAL: not a regular file, refusing to read: ${path}`), { code: 'EINVAL' });
  }
  const flag = fsConstants.O_RDONLY | (fsConstants.O_NONBLOCK ?? 0);
  return encoding ? readFile(path, { encoding, flag }) : readFile(path, { flag });
}

function toDirentInfo(e: Dirent): DirentInfo {
  return {
    name: e.name,
    isFile: e.isFile(),
    isDirectory: e.isDirectory(),
    isSymbolicLink: e.isSymbolicLink(),
    parentPath: e.parentPath,
  };
}

export class LocalFSProvider implements FSProvider {
  readonly kind = 'local' as const;
  readonly platform: Platform = process.platform;

  async readFile(path: string): Promise<string> {
    return readRegularFile(path, 'utf-8');
  }

  async readBytes(path: string): Promise<Uint8Array> {
    return readRegularFile(path);
  }

  async readdir(path: string): Promise<string[]> {
    return readdir(path);
  }

  async readdirEntries(path: string, options?: { recursive?: boolean }): Promise<DirentInfo[]> {
    if (!options?.recursive) return (await readdir(path, { withFileTypes: true })).map(toDirentInfo);
    // Node's recursive readdir rejects the whole walk on the first unreadable
    // subdirectory, so one chmod-000 folder inside a skill would hide every
    // file beside it. Walk by hand and skip what can't be listed, as the
    // probe does; only an unreadable root is an error. Symlinked directories
    // are listed, not entered.
    const results: DirentInfo[] = [];
    const pending = [path];
    for (let dir = pending.pop(); dir !== undefined; dir = pending.pop()) {
      let entries;
      try {
        entries = await readdir(dir, { withFileTypes: true });
      } catch (err) {
        if (dir === path) throw err;
        continue;
      }
      for (const e of entries) {
        results.push(toDirentInfo(e));
        if (e.isDirectory()) pending.push(join(dir, e.name));
      }
    }
    return results;
  }

  async access(path: string): Promise<boolean> {
    try {
      await fsAccess(path);
      return true;
    } catch {
      return false;
    }
  }

  async stat(path: string): Promise<{ mode: number; isFile(): boolean; isDirectory(): boolean }> {
    const s = await stat(path);
    return {
      mode: s.mode,
      isFile: () => s.isFile(),
      isDirectory: () => s.isDirectory(),
    };
  }

  async permissions(path: string): Promise<PermissionQuery> {
    // POSIX mode bits are fake on win32 — only a provider with real ACL
    // evaluation (commercial WindowsFSProvider) may answer there.
    if (this.platform === 'win32') {
      return 'unsupported';
    }
    const s = await stat(path);
    return posixPermissionFacts(s.mode);
  }

  async ownership(path: string): Promise<{ uid: number; gid: number } | undefined> {
    if (this.platform === 'win32') return undefined;
    const s = await stat(path);
    return { uid: s.uid, gid: s.gid };
  }

  private privateGroupsCache?: Promise<ReadonlyMap<number, number>>;

  privateGroups(): Promise<ReadonlyMap<number, number>> {
    this.privateGroupsCache ??= (async () => {
      if (this.platform !== 'linux') return new Map<number, number>();
      try {
        const [passwd, group] = await Promise.all([readFile('/etc/passwd', 'utf-8'), readFile('/etc/group', 'utf-8')]);
        return parsePrivateGroups(passwd, group);
      } catch {
        return new Map<number, number>();
      }
    })();
    return this.privateGroupsCache;
  }

  async realpath(path: string): Promise<string> {
    return realpath(path);
  }

  async readlink(path: string): Promise<string> {
    return readlink(path);
  }

  async exec(cmd: string, args: string[], options?: ExecOptions): Promise<ExecResult> {
    const iso = isolatedEnv(options);
    try {
      const result = await execFileAsync(cmd, args, {
        encoding: 'utf-8',
        timeout: options?.timeout ?? 10000,
        cwd: iso.cwd,
        ...(iso.env ? { env: iso.env } : {}),
      });
      return {
        stdout: result.stdout,
        stderr: result.stderr,
        exitCode: 0,
      };
    } catch (err: unknown) {
      const e = err as { stdout?: string; stderr?: string; code?: number; status?: number };
      return {
        stdout: e.stdout ?? '',
        stderr: e.stderr ?? '',
        exitCode: e.status ?? e.code ?? 1,
      };
    } finally {
      iso.cleanup();
    }
  }

  execSync(cmd: string, args: string[], options?: ExecOptions): string {
    const iso = isolatedEnv(options);
    try {
      return execFileSync(cmd, args, {
        encoding: 'utf-8',
        timeout: options?.timeout ?? 10000,
        stdio: ['pipe', 'pipe', 'pipe'],
        cwd: iso.cwd,
        ...(iso.env ? { env: iso.env } : {}),
      }).toString();
    } finally {
      iso.cleanup();
    }
  }

  isPrivileged(): boolean {
    return process.getuid?.() === 0;
  }

  homedir(): string {
    return osHomedir();
  }

  hostname(): string {
    return osHostname();
  }

  getEnv(key: string): string | undefined {
    return process.env[key];
  }
}
