export interface ProbeManifest {
  filePaths: string[];
  globPatterns: string[];
  commands: CommandRequest[];
  directoryListings: string[];
  envPrefixes: string[];
  systemPaths?: string[];
  systemDirListings?: string[];
  /** Globs recorded as metadata only (exists + mode, no content) — private
   *  data where checks need permissions, e.g. conversation stores. */
  metadataGlobPatterns?: string[];
}

export interface CommandRequest {
  id: string;
  cmd: string;
  args: string[];
  timeout?: number;
  /** Run with a throwaway HOME/XDG dirs and cwd (agent CLI version queries). */
  isolateHome?: boolean;
}

export interface ProbeSnapshot {
  version: 1;
  hostname: string;
  platform: NodeJS.Platform;
  homedir: string;
  timestamp: string;
  privilege: PrivilegeInfo;
  files: Record<string, FileEntry>;
  directories: Record<string, string[]>;
  commandOutputs: Record<string, CommandOutput>;
  env: Record<string, string>;
  /** Permission bits of listed directories and user homes (probe ≥ 1.0.0). */
  directoryModes?: Record<string, number>;
  /** The probe's content budget ran out; later files carry metadata only. */
  truncated?: boolean;
  /** Symlinks seen in listings and glob matches, path → link target (probe ≥ 1.0.1). */
  symlinks?: Record<string, string>;
  /** Owner [uid, gid] of collected files and directories (probe ≥ 1.0.1). */
  owners?: Record<string, [number, number]>;
  /** User-private groups on the host, gid → uid (probe ≥ 1.0.1, Linux). */
  privateGroups?: Record<string, number>;
}

export interface PrivilegeInfo {
  uid: number;
  username: string;
  isRoot: boolean;
  sudoAvailable: boolean;
  escalated: boolean;
  scannedUsers: string[];
  skippedPaths: string[];
}

export interface FileEntry {
  content: string;
  mode: number;
  exists: boolean;
  /** Exists, but content was deliberately not collected (size cap, content
   *  budget, binary asset, or a metadata-only glob). */
  contentOmitted?: boolean;
}

export interface CommandOutput {
  stdout: string;
  stderr: string;
  exitCode: number;
}
