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
  /** Run once per item of an earlier command's JSON output (probe ≥ 1.0.1),
   *  substituting `{field}` placeholders in `args`. Each run is stored under its
   *  natural `<cmd> <args>` key, so `fs.exec` with the substituted args finds it. */
  forEach?: CommandForEach;
}

export interface CommandForEach {
  /** `id` of an earlier command whose stdout is JSON. */
  from: string;
  /** Top-level key of the array to iterate. */
  array: string;
  /** String fields of each item, substituted for `{field}` in args. */
  fields: string[];
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
  /** `'base64'` when the file is not valid UTF-8 and `content` holds its bytes
   *  base64-encoded (probe ≥ 1.0.1); absent means UTF-8 text. */
  encoding?: 'base64';
}

export interface CommandOutput {
  stdout: string;
  stderr: string;
  exitCode: number;
}
