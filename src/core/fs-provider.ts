export interface DirentInfo {
  name: string;
  isFile: boolean;
  isDirectory: boolean;
  parentPath?: string;
}

export interface ExecResult {
  stdout: string;
  stderr: string;
  exitCode: number;
}

export interface ExecOptions {
  timeout?: number;
  encoding?: string;
  cwd?: string;
}

export interface FSProvider {
  readFile(path: string): Promise<string>;
  /**
   * Read raw bytes. LocalFSProvider returns the file's actual bytes;
   * SnapshotFSProvider returns a UTF-8 re-encoding of the collected text
   * content, which is best-effort: any bytes the probe couldn't represent
   * as valid UTF-8 were already replaced before reaching the snapshot.
   * Callers doing byte-level checks (e.g. magic-byte anchoring) should
   * treat snapshot results accordingly.
   */
  readBytes(path: string): Promise<Uint8Array>;
  readdir(path: string): Promise<string[]>;
  readdirEntries(path: string, options?: { recursive?: boolean }): Promise<DirentInfo[]>;
  access(path: string): Promise<boolean>;
  stat(path: string): Promise<{ mode: number; isFile(): boolean; isDirectory(): boolean }>;
  realpath(path: string): Promise<string>;
  exec(cmd: string, args: string[], options?: ExecOptions): Promise<ExecResult>;
  execSync(cmd: string, args: string[], options?: ExecOptions): string;
  /** Look up an environment variable. SnapshotFSProvider reads from the
   *  probe-collected env section; LocalFSProvider reads from process.env. */
  getEnv(key: string): string | undefined;
  readonly platform: NodeJS.Platform;
  homedir(): string;
  /** Hostname of the machine the scan is running against. LocalFSProvider
   *  returns `os.hostname()`; SnapshotFSProvider returns the value the probe
   *  collected. Used by checks that need to disambiguate per-host state
   *  (e.g. MCP tool-baseline keys when fleet-scanning two hosts whose
   *  configs declare the same server name with no localPath/packageName). */
  hostname(): string;
}
