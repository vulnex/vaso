import { access as fsAccess, open, readdir, readFile, stat, realpath, readlink } from 'node:fs/promises';
import { execFileSync, execFile } from 'node:child_process';
import { constants as fsConstants, type Dirent } from 'node:fs';
import { isUtf8 } from 'node:buffer';
import { dirname, join } from 'node:path';
import { homedir as osHomedir, hostname as osHostname } from 'node:os';
import { promisify } from 'node:util';
import type { FSProvider, DirentInfo, ExecResult, ExecOptions, PermissionQuery } from './fs-provider.js';
import type { Platform } from './types.js';
import { posixPermissionFacts } from './permissions.js';
import { parsePrivateGroups } from './private-groups.js';
import { planExec } from './exec-safety.js';
import { runBounded, runBoundedSync, type BoundedRunResult } from './bounded-exec.js';

const execFileAsync = promisify(execFile);

/** exec()'s exit code: execFile's (127 for a missing command, 1 when killed). */
function boundedExitCode(r: BoundedRunResult): number {
  if (r.error) return r.error.code === 'ENOENT' ? 127 : 126;
  return r.status ?? 1;
}

/**
 * Reads a regular file only. A FIFO where a config is expected would block
 * the scan forever and a device such as /dev/zero never ends; both can be
 * planted in a scanned directory. stat() follows symlinks, so a link to a
 * device is caught too; O_NONBLOCK keeps a FIFO swapped in after the check
 * from blocking (the read then sees end-of-file).
 */
async function readRegularFile(path: FsPath): Promise<Buffer>;
async function readRegularFile(path: FsPath, encoding: 'utf-8'): Promise<string>;
async function readRegularFile(path: FsPath, encoding?: 'utf-8'): Promise<Buffer | string> {
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

/** A path as the OS takes it: a string, or raw bytes for a name that isn't UTF-8. */
type FsPath = string | Buffer;

function toDirentInfo(e: Dirent<Buffer>, name: string, parentPath: string): DirentInfo {
  return {
    name,
    isFile: e.isFile(),
    isDirectory: e.isDirectory(),
    isSymbolicLink: e.isSymbolicLink(),
    parentPath,
  };
}

export class LocalFSProvider implements FSProvider {
  readonly kind = 'local' as const;
  readonly platform: Platform = process.platform;

  /**
   * Linux file names are bytes, not necessarily UTF-8 (`caf\xe9.js`). A
   * listing decodes them as the probe's JSON does — invalid sequences become
   * U+FFFD, so evidence paths match a remote scan — and remembers the raw
   * bytes under that name, so a read of the listed path reaches the file
   * instead of failing silently (a skill could hide code that way).
   */
  private readonly rawPaths = new Map<string, Buffer>();

  /** The bytes to hand the OS for a path this provider listed. */
  private fsPath(path: string): FsPath {
    if (this.rawPaths.size === 0 || !path.includes('\uFFFD')) return path;
    for (let p = path; ; p = dirname(p)) {
      const raw = this.rawPaths.get(p);
      if (raw) return Buffer.concat([raw, Buffer.from(path.slice(p.length), 'utf-8')]);
      if (dirname(p) === p) return path;
    }
  }

  /** List `dir`, decoding names and remembering raw paths that aren't UTF-8. */
  private async list(dir: string): Promise<DirentInfo[]> {
    const raw = this.fsPath(dir);
    const rawDir = typeof raw === 'string' ? undefined : raw;
    const entries = await readdir(raw, { withFileTypes: true, encoding: 'buffer' });
    return entries.map(e => {
      const name = e.name.toString('utf-8');
      if (rawDir || !isUtf8(e.name)) {
        const base = rawDir ?? Buffer.from(dir, 'utf-8');
        this.rawPaths.set(join(dir, name), Buffer.concat([base, Buffer.from(base.at(-1) === 0x2f ? '' : '/'), e.name]));
      }
      return toDirentInfo(e, name, dir);
    });
  }

  async readFile(path: string): Promise<string> {
    return readRegularFile(this.fsPath(path), 'utf-8');
  }

  async readBytes(path: string): Promise<Uint8Array> {
    return readRegularFile(this.fsPath(path));
  }

  async readHead(path: string, n: number): Promise<Uint8Array> {
    const handle = await open(this.fsPath(path), fsConstants.O_RDONLY | (fsConstants.O_NONBLOCK ?? 0));
    try {
      if (!(await handle.stat()).isFile()) {
        throw Object.assign(new Error(`EINVAL: not a regular file, refusing to read: ${path}`), { code: 'EINVAL' });
      }
      const buf = Buffer.alloc(n);
      const { bytesRead } = await handle.read(buf, 0, n, 0);
      return buf.subarray(0, bytesRead);
    } finally {
      await handle.close();
    }
  }

  async readdir(path: string): Promise<string[]> {
    return (await this.list(path)).map(e => e.name);
  }

  async readdirEntries(path: string, options?: { recursive?: boolean }): Promise<DirentInfo[]> {
    if (!options?.recursive) return this.list(path);
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
        entries = await this.list(dir);
      } catch (err) {
        if (dir === path) throw err;
        continue;
      }
      for (const e of entries) {
        results.push(e);
        if (e.isDirectory) pending.push(join(dir, e.name));
      }
    }
    return results;
  }

  async access(path: string): Promise<boolean> {
    try {
      await fsAccess(this.fsPath(path));
      return true;
    } catch {
      return false;
    }
  }

  async stat(path: string): Promise<{ mode: number; isFile(): boolean; isDirectory(): boolean }> {
    const s = await stat(this.fsPath(path));
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
    const s = await stat(this.fsPath(path));
    return posixPermissionFacts(s.mode);
  }

  async ownership(path: string): Promise<{ uid: number; gid: number } | undefined> {
    if (this.platform === 'win32') return undefined;
    const s = await stat(this.fsPath(path));
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
    return realpath(this.fsPath(path));
  }

  async readlink(path: string): Promise<string> {
    return readlink(this.fsPath(path));
  }

  async exec(cmd: string, args: string[], options?: ExecOptions): Promise<ExecResult> {
    const plan = planExec(cmd, options);
    if (plan.refuse) return { stdout: '', stderr: plan.refuse, exitCode: 126 };
    const timeout = options?.timeout ?? 10000;
    if (this.platform !== 'win32') {
      // Bounded by the timeout even when the command leaves a background
      // process holding its output (bounded-exec.ts)
      try {
        const r = await runBounded(cmd, args, { timeout, cwd: plan.cwd, env: plan.env, uid: plan.uid, gid: plan.gid });
        return { stdout: r.stdout, stderr: r.stderr, exitCode: boundedExitCode(r) };
      } catch (err) {
        return { stdout: '', stderr: (err as Error).message, exitCode: 1 };
      } finally {
        plan.cleanup();
      }
    }
    try {
      const result = await execFileAsync(cmd, args, {
        encoding: 'utf-8',
        timeout,
        cwd: plan.cwd,
        ...(plan.env ? { env: plan.env } : {}),
        ...(plan.uid !== undefined ? { uid: plan.uid, gid: plan.gid } : {}),
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
      plan.cleanup();
    }
  }

  execSync(cmd: string, args: string[], options?: ExecOptions): string {
    const plan = planExec(cmd, options);
    if (plan.refuse) throw new Error(plan.refuse);
    const timeout = options?.timeout ?? 10000;
    try {
      if (this.platform !== 'win32') {
        const r = runBoundedSync(cmd, args, { timeout, cwd: plan.cwd, env: plan.env, uid: plan.uid, gid: plan.gid });
        if (r.error) throw r.error;
        if (r.timedOut || r.status !== 0) {
          // Shaped like execFileSync's error: callers read status/stdout/stderr
          const why = r.timedOut ? `timed out after ${timeout} ms` : r.signal ? `killed by ${r.signal}` : `exit ${r.status}`;
          throw Object.assign(new Error(`Command failed (${why}): ${cmd} ${args.join(' ')}`), {
            status: r.status ?? null,
            signal: r.signal ?? null,
            stdout: r.stdout,
            stderr: r.stderr,
            ...(r.timedOut ? { code: 'ETIMEDOUT' } : {}),
          });
        }
        return r.stdout;
      }
      return execFileSync(cmd, args, {
        encoding: 'utf-8',
        timeout,
        stdio: ['pipe', 'pipe', 'pipe'],
        cwd: plan.cwd,
        ...(plan.env ? { env: plan.env } : {}),
        ...(plan.uid !== undefined ? { uid: plan.uid, gid: plan.gid } : {}),
      }).toString();
    } finally {
      plan.cleanup();
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
