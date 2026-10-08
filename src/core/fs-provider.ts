import type { Platform } from './types.js';
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

/**
 * Provider-neutral answer to "who besides the owner can touch this path".
 *
 * On POSIX the facts are derived from mode bits (group/world triads). A
 * Windows provider derives them from ACL evaluation instead — grants to
 * Everyone map to the `world*` flags, grants to Users / Authenticated Users
 * to the `group*` flags — so checks written against these facts are
 * platform-neutral without ever seeing win32's fake mode bits.
 */
export interface PermissionFacts {
  groupRead: boolean;
  groupWrite: boolean;
  groupExec: boolean;
  worldRead: boolean;
  worldWrite: boolean;
  worldExec: boolean;
  /**
   * Octal permission string like "644" when the facts came from POSIX mode
   * bits; unset when they came from ACLs. Checks embed it in evidence
   * snippets that historically printed the raw mode.
   */
  octal?: string;
  /** Short human description of the source, e.g. `mode 644` or an ACL grant summary. */
  description: string;
}

/**
 * Tri-state permission answer (see devnotes commercial design §3): facts when
 * the provider can genuinely evaluate them, `'unsupported'` when it cannot
 * (e.g. POSIX providers on win32, where mode bits are fake). Checks must
 * treat `'unsupported'` as "cannot evaluate" and skip cleanly — never as
 * "safe" or "unsafe".
 */
export type PermissionQuery = PermissionFacts | 'unsupported';

export interface ExecResult {
  stdout: string;
  stderr: string;
  exitCode: number;
}

export interface ExecOptions {
  timeout?: number;
  encoding?: string;
  cwd?: string;
  /** Run with HOME/XDG dirs and cwd pointed at a throwaway directory that is
   *  removed afterwards. Used for agent CLI version queries: several CLIs
   *  initialize state in the user's home on any invocation (Hermes creates
   *  ~/.hermes, Cursor ~/.cursor/cli-config.json, …), and a scan must not
   *  modify what it scans. */
  isolateHome?: boolean;
}

export interface FSProvider {
  readFile(path: string): Promise<string>;
  /**
   * Read raw bytes. LocalFSProvider returns the file's actual bytes, and so
   * does SnapshotFSProvider for snapshots from probe ≥ 1.1.0 (non-UTF-8 files
   * are shipped base64-encoded). From older probes it returns a UTF-8
   * re-encoding of the collected text, where invalid byte sequences were
   * already replaced — byte-level checks must treat those accordingly.
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
   * path is not a symlink. SnapshotFSProvider answers from the targets the
   * probe recorded (probe ≥ 1.1.0) and throws otherwise.
   */
  readlink(path: string): Promise<string>;
  /**
   * Semantic permission query (tri-state — see PermissionQuery). Optional
   * capability: providers that can evaluate real permissions implement it;
   * checks go through `queryPermissions()` in core/permissions.ts, which
   * prefers this method and otherwise falls back to POSIX mode bits from
   * `stat()` — or `'unsupported'` on win32, so mode math is never trusted
   * there. A Windows ACL provider makes win32 answerable by implementing
   * this method.
   */
  permissions?(path: string): Promise<PermissionQuery>;
  /** Owner uid/gid of a path (POSIX). Optional; undefined means unknown. */
  ownership?(path: string): Promise<{ uid: number; gid: number } | undefined>;
  /** User-private groups on the scanned host: gid → the one user (uid) it
   *  serves (see core/private-groups.ts). Optional; Linux only. */
  privateGroups?(): Promise<ReadonlyMap<number, number>>;
  exec(cmd: string, args: string[], options?: ExecOptions): Promise<ExecResult>;
  execSync(cmd: string, args: string[], options?: ExecOptions): string;
  /** Look up an environment variable. SnapshotFSProvider reads from the
   *  probe-collected env section; LocalFSProvider reads from process.env. */
  getEnv(key: string): string | undefined;
  readonly platform: Platform;
  /** `'snapshot'` when commands were collected ahead of time by the probe:
   *  `exec` then answers by command name, so running a second copy of a CLI
   *  by full path returns the first copy's output. Absent → treated as live. */
  readonly kind?: 'local' | 'snapshot';
  /** True when the scan runs with root privileges on the scanned host (so
   *  other users' homes are readable). LocalFSProvider checks the process
   *  uid; SnapshotFSProvider reports the probe's privilege. Absent → false. */
  isPrivileged?(): boolean;
  homedir(): string;
  /** Hostname of the machine the scan is running against. LocalFSProvider
   *  returns `os.hostname()`; SnapshotFSProvider returns the value the probe
   *  collected. Used by checks that need to disambiguate per-host state
   *  (e.g. MCP tool-baseline keys when fleet-scanning two hosts whose
   *  configs declare the same server name with no localPath/packageName). */
  hostname(): string;
}
