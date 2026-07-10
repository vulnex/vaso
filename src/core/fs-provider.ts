export interface DirentInfo {
  name: string;
  isFile: boolean;
  isDirectory: boolean;
  /**
   * True when the entry is a symbolic link (from an lstat-style read that does
   * not follow the link). `isFile`/`isDirectory` reflect the link itself, not
   * its target, so a symlink to a regular file has all three of `isFile:false`,
   * `isDirectory:false`, `isSymbolicLink:true`. Optional because providers that
   * cannot observe link status (SnapshotFSProvider, test mocks) leave it unset;
   * consumers treat unset as "not a symlink".
   */
  isSymbolicLink?: boolean;
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
  /**
   * Return the raw target of a symbolic link without resolving it. Unlike
   * `realpath`, this does not require the target to exist (a dangling symlink
   * to `~/.ssh/authorized_keys` planted by a malicious repo still returns its
   * literal target), and it does not follow multi-hop chains — it reports one
   * link's own target string as stored on disk (may be relative). Throws if the
   * path is not a symlink. SnapshotFSProvider throws (link data isn't collected).
   */
  readlink(path: string): Promise<string>;
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
