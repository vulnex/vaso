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
  /** Variables (exact names) recorded only as set or not: the probe (newer than
   *  1.4.0) stores ENV_PRESENT_VALUE when one is non-empty after trimming, and
   *  nothing otherwise — never its value. */
  envPresence?: string[];
  /** Paths an agent's config sets — a workspace, an extra skills directory,
   *  an MCP server's command — read by the probe (newer than 1.4.1) from the
   *  configs it collects. Older probes ignore it. */
  configRoots?: ConfigRootRequest[];
  /** Private store folders (Copilot's session-state/, …): the probe (newer
   *  than 1.4.1) records a link from one to a place that isn't the agent's —
   *  the folder itself or one linked directly inside it, judged by
   *  foreignStoreTarget (src/core/store-links.ts) — as a link only, and
   *  collects nothing behind it. Older probes ignore it. */
  privateStores?: string[];
}

/**
 * One kind of config-set path. The probe parses each config (JSON/JSONC/
 * JSON5, TOML, or block-style YAML), takes the string values at `keys`, and
 * either walks each value as a skill tree (`tree`: `globs` under it, content
 * disguised like a config's; walked only strictly inside the home of the user
 * whose config names it and outside credential stores, refused otherwise —
 * see src/core/skill-root-scope.ts) or stats it (`stat`:
 * existence, mode and owner — never content; absolute paths only, keyed as
 * the config spells them).
 */
export interface ConfigRootRequest {
  /** Config files, in manifest path syntax (`~`, `${VAR}`, globs). Empty,
   *  with `envFallback` set: that variable's value alone, for the probe's
   *  own user (probe ≥ 1.4.2; older probes collect nothing for it). */
  configs: string[];
  format: 'json' | 'toml' | 'yaml';
  /** Key paths; `*` is every key of a mapping or item of an array. */
  keys: string[][];
  kind: 'tree' | 'stat';
  /** tree: globs relative to each value, each `**` or ending in `/**`. */
  globs?: string[];
  /** A relative value resolves against the scanned home, the config's
   *  directory, or the directory above it (`configParent`: a plugin root,
   *  for `<root>/.claude-plugin/plugin.json`); omitted: relative values are
   *  skipped (the adapter resolves them against its working directory,
   *  which the probe can't know). */
  relative?: 'home' | 'config' | 'configParent';
  /** Expand `${NAME}` in values from the environment (unset: skipped). */
  expandEnv?: boolean;
  /** When no key holds a string: this variable's value. */
  envFallback?: string;
  /** Only when this key path is boolean true in the same config. */
  when?: string[];
  /** Used when `when` holds and no key holds a string. */
  default?: string;
  /** Walked before the manifest's globs, which would otherwise collect the
   *  tree as plain files first (probe ≥ 1.4.2; older probes walk it after). */
  beforeGlobs?: boolean;
}

/** What the probe did with a config-derived tree (`ProbeSnapshot.configTrees`). */
export type ConfigTreeStatus = 'collected' | 'refused' | 'limit' | 'total';

/** What a snapshot holds for an envPresence variable that is set. */
export const ENV_PRESENT_VALUE = 'set';

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
  /** `directoryModes` carry the setuid/setgid/sticky bits (0o7000) too, so a
   *  0o777 directory is known not to be sticky. Older probes record the
   *  permission bits only: whether a world-writable directory is sticky is
   *  unknown there. */
  specialModeBits?: boolean;
  /** The probe's content budget ran out; later files carry metadata only. */
  truncated?: boolean;
  /** Symlinks seen in listings and glob matches, path → link target (probe ≥ 1.1.0). */
  symlinks?: Record<string, string>;
  /** Owner [uid, gid] of collected files and directories (probe ≥ 1.1.0). */
  owners?: Record<string, [number, number]>;
  /** Owner [uid, gid] of the links in `symlinks` the probe recorded a chain
   *  for, the link itself (lstat) — who can rename it (probe newer than 1.4.1). */
  linkOwners?: Record<string, [number, number]>;
  /** User-private groups on the host, gid → uid (probe ≥ 1.1.0, Linux). */
  privateGroups?: Record<string, number>;
  /** Config-derived trees (probe newer than 1.4.1), by literal base path (a
   *  wildcard base is recorded per match): collected (absent files are
   *  absent), refused (a base no tree is walked from) or over the probe's
   *  entry limit (not collected). At most 2000; compared as plain strings.
   *  Also (probe ≥ 1.5.0) each directory link in a skills tree not followed
   *  for size — over the entry limit (`limit`) or past what the tree's links
   *  may hold together (`total`) — at most 20000 more. */
  configTrees?: Record<string, ConfigTreeStatus>;
  /** More links in skills trees went unfollowed for size than configTrees
   *  records: after that the probe still followed the links its plan
   *  follows, and recorded no others (probe ≥ 1.5.0; linkCap). */
  skillLinksTruncated?: boolean;
  /** Where a scanned home — or a directory naming a home the other way, met
   *  as a config tree's wildcard directory — resolves to, when that differs
   *  from its spelling (probe newer than 1.4.1). Read only when judging
   *  config-set skills directories (skill-root-scope.ts). */
  resolvedDirs?: Record<string, string>;
  /** For a config tree's wildcard directory directly in a home (which the
   *  probe never lists): the names its wildcard segment matches there, keyed
   *  `<dir>/<segment>` (`/home/u/workspace-*`). Read only for segments of
   *  this CLI's own manifest, never compiled (probe-coverage.ts). */
  wildcardNames?: Record<string, string[]>;
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
   *  (probe ≥ 1.3.1) — where an executable header sits: 64 bytes up to 1.4.0,
   *  then 4 KiB or up to a PE stub's header at e_lfanew (≤ 1 MiB). */
  head?: string;
  /** `'base64'` when the file is not valid UTF-8 and `content` holds its bytes
   *  base64-encoded (probe ≥ 1.1.0); absent means UTF-8 text. */
  encoding?: 'base64';
  /** Permission denied (probe ≥ 1.3.1): stat failed (exists false — inside a
   *  chmod-000 directory) or the file can't be opened (exists true, mode set). */
  denied?: boolean;
  /** The credential-store file this one is a hard link to (probe ≥ 1.5.0;
   *  omitted `sensitive`): SKL-013 reports it like a link into that store. */
  hardLinkOf?: string;
}

export interface CommandOutput {
  stdout: string;
  stderr: string;
  exitCode: number;
}
