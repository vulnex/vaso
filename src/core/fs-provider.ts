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
  readdir(path: string): Promise<string[]>;
  readdirEntries(path: string, options?: { recursive?: boolean }): Promise<DirentInfo[]>;
  access(path: string): Promise<boolean>;
  stat(path: string): Promise<{ mode: number; isFile(): boolean; isDirectory(): boolean }>;
  realpath(path: string): Promise<string>;
  exec(cmd: string, args: string[], options?: ExecOptions): Promise<ExecResult>;
  execSync(cmd: string, args: string[], options?: ExecOptions): string;
  readonly platform: NodeJS.Platform;
  homedir(): string;
}
