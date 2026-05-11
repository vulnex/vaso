import { join, basename } from 'node:path';
import type { FSProvider, DirentInfo, ExecResult, ExecOptions } from './fs-provider.js';
import type { ProbeSnapshot } from './snapshot-types.js';

function stripTrailingSlash(name: string): string {
  return name.endsWith('/') ? name.slice(0, -1) : name;
}

export class SnapshotFSProvider implements FSProvider {
  readonly platform: NodeJS.Platform;
  private snapshot: ProbeSnapshot;

  constructor(snapshot: ProbeSnapshot) {
    this.snapshot = snapshot;
    this.platform = snapshot.platform as NodeJS.Platform;
  }

  async readFile(path: string): Promise<string> {
    const entry = this.snapshot.files[path];
    if (!entry || !entry.exists) {
      throw new Error(`ENOENT: file not collected in snapshot: ${path}`);
    }
    return entry.content;
  }

  async readBytes(path: string): Promise<Uint8Array> {
    const entry = this.snapshot.files[path];
    if (!entry || !entry.exists) {
      throw new Error(`ENOENT: file not collected in snapshot: ${path}`);
    }
    // The probe stored the file as a UTF-8 string. We re-encode it here on
    // the same encoding so ASCII-safe content (most source files, including
    // ELF/PE magics whose first bytes are valid UTF-8 single-byte codepoints)
    // roundtrips faithfully. Non-UTF-8 byte sequences were already replaced
    // with U+FFFD by the probe and can't be recovered.
    return Buffer.from(entry.content, 'utf-8');
  }

  async readdir(path: string): Promise<string[]> {
    const listing = this.snapshot.directories[path];
    if (listing) {
      // The Go probe appends '/' to directory entry names so callers can tell
      // dirs from files in a flat string list. We strip it here so consumers
      // get clean basenames usable for path.join() without producing '//'.
      return listing.map(stripTrailingSlash);
    }

    // Try to derive directory listing from collected files
    const entries = new Set<string>();
    const prefix = path.endsWith('/') ? path : path + '/';
    for (const filePath of Object.keys(this.snapshot.files)) {
      if (filePath.startsWith(prefix)) {
        const relative = filePath.slice(prefix.length);
        const firstSegment = relative.split('/')[0];
        if (firstSegment) entries.add(firstSegment);
      }
    }
    for (const dirPath of Object.keys(this.snapshot.directories)) {
      if (dirPath.startsWith(prefix) && dirPath !== path) {
        const relative = dirPath.slice(prefix.length);
        const firstSegment = relative.split('/')[0];
        if (firstSegment) entries.add(firstSegment);
      }
    }

    if (entries.size > 0) return [...entries];
    throw new Error(`ENOENT: directory not collected in snapshot: ${path}`);
  }

  async readdirEntries(path: string, options?: { recursive?: boolean }): Promise<DirentInfo[]> {
    if (options?.recursive) {
      return this.readdirRecursive(path);
    }

    const names = await this.readdir(path);
    return names.map(name => {
      const fullPath = join(path, name);
      const isFile = fullPath in this.snapshot.files && this.snapshot.files[fullPath].exists;
      const isDir = fullPath in this.snapshot.directories ||
        this.hasChildPaths(fullPath);
      return {
        name,
        isFile: isFile && !isDir,
        isDirectory: isDir,
        parentPath: path,
      };
    });
  }

  async access(path: string): Promise<boolean> {
    const fileEntry = this.snapshot.files[path];
    if (fileEntry?.exists) return true;
    if (this.directoryExists(path)) return true;
    // Check if any collected path starts with this as a directory
    if (this.hasChildPaths(path)) return true;
    return false;
  }

  async stat(path: string): Promise<{ mode: number; isFile(): boolean; isDirectory(): boolean }> {
    const fileEntry = this.snapshot.files[path];
    if (fileEntry?.exists) {
      return {
        mode: fileEntry.mode,
        isFile: () => true,
        isDirectory: () => false,
      };
    }
    if (this.directoryExists(path) || this.hasChildPaths(path)) {
      return {
        mode: 0o755,
        isFile: () => false,
        isDirectory: () => true,
      };
    }
    throw new Error(`ENOENT: path not collected in snapshot: ${path}`);
  }

  async realpath(path: string): Promise<string> {
    // Snapshots don't resolve symlinks — return as-is if path exists
    if (await this.access(path)) return path;
    throw new Error(`ENOENT: path not collected in snapshot: ${path}`);
  }

  async exec(cmd: string, args: string[], _options?: ExecOptions): Promise<ExecResult> {
    const output = this.findCommandOutput(cmd, args);
    if (!output) {
      return {
        stdout: '',
        stderr: `Command not collected in snapshot: ${cmd} ${args.join(' ')}`,
        exitCode: 127,
      };
    }
    return {
      stdout: output.stdout,
      stderr: output.stderr,
      exitCode: output.exitCode,
    };
  }

  execSync(cmd: string, args: string[], _options?: ExecOptions): string {
    const output = this.findCommandOutput(cmd, args);
    if (!output) {
      throw new Error(`Command not collected in snapshot: ${cmd} ${args.join(' ')}`);
    }
    if (output.exitCode !== 0) {
      throw new Error(`Command failed (exit ${output.exitCode}): ${output.stderr}`);
    }
    return output.stdout;
  }

  homedir(): string {
    return this.snapshot.homedir;
  }

  getEnv(key: string): string | undefined {
    return this.snapshot.env?.[key];
  }

  get hostname(): string {
    return this.snapshot.hostname;
  }

  get privilege() {
    return this.snapshot.privilege;
  }

  /**
   * Returns true only when the snapshot has an explicit, non-null listing for
   * the given directory. Older probes (and the Go zero-value behaviour) could
   * insert keys with `null` listings when `os.ReadDir` failed for a missing
   * directory; treating those as "exists" produces false-positive agent
   * detections, so they're filtered out here.
   */
  private directoryExists(path: string): boolean {
    if (!(path in this.snapshot.directories)) return false;
    const listing = this.snapshot.directories[path];
    return Array.isArray(listing);
  }

  private hasChildPaths(path: string): boolean {
    const prefix = path.endsWith('/') ? path : path + '/';
    for (const [key, entry] of Object.entries(this.snapshot.files)) {
      if (key.startsWith(prefix) && entry.exists) return true;
    }
    for (const [key, listing] of Object.entries(this.snapshot.directories)) {
      if (key.startsWith(prefix) && Array.isArray(listing)) return true;
    }
    return false;
  }

  private readdirRecursive(basePath: string): DirentInfo[] {
    const results: DirentInfo[] = [];
    const prefix = basePath.endsWith('/') ? basePath : basePath + '/';

    for (const [filePath, entry] of Object.entries(this.snapshot.files)) {
      if (!filePath.startsWith(prefix) || !entry.exists) continue;
      const relative = filePath.slice(prefix.length);
      const name = relative.split('/').pop() || relative;
      const parentPath = filePath.slice(0, filePath.length - name.length - 1) || basePath;
      results.push({
        name,
        isFile: true,
        isDirectory: false,
        parentPath,
      });
    }

    return results;
  }

  private findCommandOutput(cmd: string, args: string[]) {
    // Try exact id match first against both the raw cmd and its basename, so
    // adapters that resolve cliBinary to a full path (e.g. /usr/local/bin/codex
    // --version) still match snapshot entries keyed by the bare command name.
    const cmdBase = basename(cmd);
    const fullKey = `${cmd} ${args.join(' ')}`.trim();
    if (this.snapshot.commandOutputs[fullKey]) {
      return this.snapshot.commandOutputs[fullKey];
    }
    if (cmdBase !== cmd) {
      const baseKey = `${cmdBase} ${args.join(' ')}`.trim();
      if (this.snapshot.commandOutputs[baseKey]) {
        return this.snapshot.commandOutputs[baseKey];
      }
    }

    // Special case: `which <bin>` is collected by manifests as `<bin>-which`.
    // Translate the lookup so adapter fallbacks (`fs.execSync('which', ['openclaw'])`)
    // resolve to the snapshot entry collected on the remote host.
    if (cmdBase === 'which' && args.length > 0) {
      const target = basename(args[0]);
      const whichId = `${target}-which`;
      if (this.snapshot.commandOutputs[whichId]) {
        return this.snapshot.commandOutputs[whichId];
      }
    }

    // Try matching by command name and args pattern
    for (const [id, output] of Object.entries(this.snapshot.commandOutputs)) {
      // Match ids like "netstat-tcp" against cmd "netstat" with args containing "tcp"
      const idParts = id.split('-');
      if (idParts[0] === cmdBase || id.startsWith(cmdBase)) {
        // Heuristic: if the id starts with the command name, it's likely a match
        // Check if args overlap with id components
        const idLower = id.toLowerCase();
        if (idLower.includes(cmdBase) && (args.length === 0 || this.argsMatchId(id, cmdBase, args))) {
          return output;
        }
      }
    }

    // Try by command-args key format: "cmd arg1 arg2"
    return undefined;
  }

  private argsMatchId(id: string, cmd: string, args: string[]): boolean {
    // Extract the part after the command name in the id
    const suffix = id.slice(cmd.length).replace(/^[-_]/, '');
    if (!suffix) return true;
    // Check if any arg fragment appears in the suffix
    return args.some(arg => {
      const cleaned = arg.replace(/^-+/, '');
      return suffix.toLowerCase().includes(cleaned.toLowerCase());
    });
  }
}
