export interface ProbeManifest {
  filePaths: string[];
  globPatterns: string[];
  commands: CommandRequest[];
  directoryListings: string[];
  envPrefixes: string[];
  systemPaths?: string[];
  systemDirListings?: string[];
}

export interface CommandRequest {
  id: string;
  cmd: string;
  args: string[];
  timeout?: number;
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
}

export interface CommandOutput {
  stdout: string;
  stderr: string;
  exitCode: number;
}
