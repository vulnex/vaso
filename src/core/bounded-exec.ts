import { spawn, spawnSync, type SpawnOptions } from 'node:child_process';
import { closeSync, fstatSync, mkdtempSync, openSync, readSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

/**
 * Runs a command found on the scanned host (an agent CLI's `--version`, `which`)
 * so that it can't hold the scan past its timeout. With pipes, Node waits for
 * every process that inherited them: a shim that leaves `( sleep 30 ) &` behind
 * kept a local scan waiting 30 s after it printed its version, timeout or not.
 * Output goes to private temp files instead (the child's exit is what's awaited),
 * the command runs in its own process group, and the group — whatever it left
 * running — is killed once it exits or times out. The probe does the same
 * (runCommand in probe/collector.go). POSIX only; win32 keeps execFile.
 */

/** Output kept per stream, like execFile's default maxBuffer. */
const MAX_OUTPUT_BYTES = 1024 * 1024;

export interface BoundedRunOptions {
  timeout: number;
  cwd?: string;
  env?: NodeJS.ProcessEnv;
  uid?: number;
  gid?: number;
}

export interface BoundedRunResult {
  stdout: string;
  stderr: string;
  /** Exit status; undefined when killed by a signal or it never started. */
  status?: number;
  signal?: NodeJS.Signals;
  timedOut: boolean;
  /** Spawn failure (ENOENT, EACCES). */
  error?: NodeJS.ErrnoException;
}

interface OutputFiles {
  out: number;
  err: number;
  read(): { stdout: string; stderr: string };
}

function outputFiles(): OutputFiles {
  let dir: string;
  try {
    dir = mkdtempSync(join(tmpdir(), 'vaso-out-'));
  } catch {
    dir = mkdtempSync('/tmp/vaso-out-'); // TMPDIR unusable, as planExec falls back
  }
  const out = openSync(join(dir, 'out'), 'w+', 0o600);
  const err = openSync(join(dir, 'err'), 'w+', 0o600);
  const readFd = (fd: number): string => {
    // The child shares this file description, so read from offset 0
    const size = Math.min(fstatSync(fd).size, MAX_OUTPUT_BYTES);
    const buf = Buffer.alloc(size);
    let n = 0;
    while (n < size) {
      const got = readSync(fd, buf, n, size - n, n);
      if (got === 0) break;
      n += got;
    }
    return buf.subarray(0, n).toString('utf-8');
  };
  return {
    out,
    err,
    read() {
      try {
        return { stdout: readFd(out), stderr: readFd(err) };
      } finally {
        closeSync(out);
        closeSync(err);
        rmSync(dir, { recursive: true, force: true });
      }
    },
  };
}

/** Kill the process group led by `pid` (the command and anything it left behind). */
function killGroup(pid: number | undefined): void {
  if (!pid) return;
  try {
    process.kill(-pid, 'SIGKILL');
  } catch {
    // already gone
  }
}

function spawnOptions(o: BoundedRunOptions, files: OutputFiles): SpawnOptions {
  return {
    cwd: o.cwd,
    env: o.env,
    detached: true, // own process group, so the whole group can be killed
    stdio: ['ignore', files.out, files.err],
    ...(o.uid !== undefined ? { uid: o.uid, gid: o.gid } : {}),
  };
}

export function runBoundedSync(cmd: string, args: string[], o: BoundedRunOptions): BoundedRunResult {
  const files = outputFiles();
  // spawnSync honours `detached` (the child leads its own group)
  const r = spawnSync(cmd, args, { ...spawnOptions(o, files), timeout: o.timeout, killSignal: 'SIGKILL' });
  killGroup(r.pid);
  const { stdout, stderr } = files.read();
  const error = r.error as NodeJS.ErrnoException | undefined;
  const timedOut = error?.code === 'ETIMEDOUT';
  return {
    stdout,
    stderr,
    status: r.status ?? undefined,
    signal: r.signal ?? undefined,
    timedOut,
    error: timedOut ? undefined : error,
  };
}

export function runBounded(cmd: string, args: string[], o: BoundedRunOptions): Promise<BoundedRunResult> {
  const files = outputFiles();
  return new Promise(resolve => {
    let timedOut = false;
    let settled = false;
    let timer: NodeJS.Timeout | undefined;
    const finish = (r: Omit<BoundedRunResult, 'stdout' | 'stderr' | 'timedOut'>) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      resolve({ ...files.read(), timedOut, ...r });
    };
    let child;
    try {
      child = spawn(cmd, args, spawnOptions(o, files));
    } catch (err) {
      finish({ error: err as NodeJS.ErrnoException });
      return;
    }
    timer = setTimeout(() => {
      timedOut = true;
      killGroup(child.pid);
    }, o.timeout);
    child.on('error', err => {
      killGroup(child.pid);
      finish({ error: err as NodeJS.ErrnoException });
    });
    child.on('exit', (code, signal) => {
      killGroup(child.pid);
      finish({ status: code ?? undefined, signal: signal ?? undefined });
    });
  });
}
