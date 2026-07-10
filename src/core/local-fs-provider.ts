import { access as fsAccess, readdir, readFile, stat, realpath, readlink } from 'node:fs/promises';
import { execFileSync, execFile } from 'node:child_process';
import { homedir as osHomedir, hostname as osHostname } from 'node:os';
import { promisify } from 'node:util';
import type { FSProvider, DirentInfo, ExecResult, ExecOptions } from './fs-provider.js';

const execFileAsync = promisify(execFile);

export class LocalFSProvider implements FSProvider {
  readonly platform = process.platform;

  async readFile(path: string): Promise<string> {
    return readFile(path, 'utf-8');
  }

  async readBytes(path: string): Promise<Uint8Array> {
    return readFile(path);
  }

  async readdir(path: string): Promise<string[]> {
    return readdir(path);
  }

  async readdirEntries(path: string, options?: { recursive?: boolean }): Promise<DirentInfo[]> {
    const entries = await readdir(path, {
      withFileTypes: true,
      recursive: options?.recursive ?? false,
    });
    return entries.map(e => ({
      name: e.name,
      isFile: e.isFile(),
      isDirectory: e.isDirectory(),
      isSymbolicLink: e.isSymbolicLink(),
      parentPath: e.parentPath,
    }));
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

  async realpath(path: string): Promise<string> {
    return realpath(path);
  }

  async readlink(path: string): Promise<string> {
    return readlink(path);
  }

  async exec(cmd: string, args: string[], options?: ExecOptions): Promise<ExecResult> {
    try {
      const result = await execFileAsync(cmd, args, {
        encoding: 'utf-8',
        timeout: options?.timeout ?? 10000,
        cwd: options?.cwd,
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
    }
  }

  execSync(cmd: string, args: string[], options?: ExecOptions): string {
    return execFileSync(cmd, args, {
      encoding: 'utf-8',
      timeout: options?.timeout ?? 10000,
      stdio: ['pipe', 'pipe', 'pipe'],
      cwd: options?.cwd,
    }).toString();
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
