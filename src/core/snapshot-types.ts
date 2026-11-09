import type { Platform } from './types.js';
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
  /** Collected variables (exact names) whose URL value the probe (newer than 1.4.0)
   *  keeps only up to its origin — path, query and fragment become
   *  placeholders. For endpoint overrides where checks judge the host. */
  envOriginOnly?: string[];
}

export interface CommandRequest {
  id: string;
  cmd: string;
  args: string[];
  timeout?: number;
  /** Run with a throwaway HOME/XDG dirs and cwd (agent CLI version queries). */
  isolateHome?: boolean;
  /** Run once per item of an earlier command's JSON output (probe ≥ 1.1.0),
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
  /** Value for a field an item lacks (null/empty) — e.g. an OpenShell sandbox
   *  listed without a workspace lives in `default` (probe ≥ 1.3.0; older probes skip the item). */
  defaults?: Record<string, string>;
}

export interface ProbeSnapshot {
  version: 1;
  /** Build of the probe that collected it (probe ≥ 1.3.1; absent from older probes). */
  probeVersion?: string;
  hostname: string;
  platform: Platform;
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
  /** Symlinks seen in listings and glob matches, path → link target (probe ≥ 1.1.0). */
  symlinks?: Record<string, string>;
  /** Owner [uid, gid] of collected files and directories (probe ≥ 1.1.0). */
  owners?: Record<string, [number, number]>;
  /** User-private groups on the host, gid → uid (probe ≥ 1.1.0, Linux). */
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
  /** Why the content was omitted (probe ≥ 1.3.1; `sensitive` ≥ 1.4.0: reached
   *  through a symlink into a credential store or shell startup file). */
  omitted?: 'size' | 'budget' | 'asset' | 'metadata' | 'special' | 'sensitive';
  /** First bytes (base64) of a skill-tree file omitted for size or budget
   *  (probe ≥ 1.3.1) — where an executable header sits. */
  head?: string;
  /** `'base64'` when the file is not valid UTF-8 and `content` holds its bytes
   *  base64-encoded (probe ≥ 1.1.0); absent means UTF-8 text. */
  encoding?: 'base64';
  /** Permission denied (probe ≥ 1.3.1): stat failed (exists false — inside a
   *  chmod-000 directory) or the file can't be opened (exists true, mode set). */
  denied?: boolean;
}

export interface CommandOutput {
  stdout: string;
  stderr: string;
  exitCode: number;
}
