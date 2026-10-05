import { join, basename } from 'node:path';
import type { FSProvider, DirentInfo, ExecResult, ExecOptions, PermissionQuery } from './fs-provider.js';
import { posixPermissionFacts } from './permissions.js';
import type { ProbeSnapshot } from './snapshot-types.js';

function stripTrailingSlash(name: string): string {
  return name.endsWith('/') ? name.slice(0, -1) : name;
}

export class SnapshotFSProvider implements FSProvider {
  readonly kind = 'snapshot' as const;
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
    if (entry.contentOmitted || typeof entry.content !== 'string') {
      // Present on the host, content deliberately not shipped (size cap,
      // budget, binary asset, metadata-only glob) — unreadable, not empty.
      throw new Error(`EACCES: content not collected in snapshot: ${path}`);
    }
    return entry.content;
  }

  async readBytes(path: string): Promise<Uint8Array> {
    const entry = this.snapshot.files[path];
    if (!entry || !entry.exists) {
      throw new Error(`ENOENT: file not collected in snapshot: ${path}`);
    }
    if (entry.contentOmitted || typeof entry.content !== 'string') {
      throw new Error(`EACCES: content not collected in snapshot: ${path}`);
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
    // Files the probe looked for but did not find are recorded with
    // exists: false — they must not appear in a synthesized listing.
    for (const [filePath, entry] of Object.entries(this.snapshot.files)) {
      if (entry.exists && filePath.startsWith(prefix)) {
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

    // The probe marks directory entries with a trailing '/'; readdir() strips
    // it, so read the raw listing to keep that information.
    const rawDirs = new Set(
      (this.snapshot.directories[path] ?? []).filter(n => n.endsWith('/')).map(stripTrailingSlash));
    const names = await this.readdir(path);
    const symlinks = this.snapshot.symlinks ?? {};
    return names.map(name => {
      const fullPath = join(path, name);
      // Like a local readdir: a symlink is listed as a link, never as the
      // file or directory it points to
      if (fullPath in symlinks) {
        return { name, isFile: false, isDirectory: false, isSymbolicLink: true, parentPath: path };
      }
      const isFile = fullPath in this.snapshot.files && this.snapshot.files[fullPath].exists;
      const isDir = rawDirs.has(name) || fullPath in this.snapshot.directories ||
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
        // Real mode when the probe recorded it; 0o755 is a placeholder only —
        // permission checks go through permissions(), which won't guess.
        mode: this.snapshot.directoryModes?.[path] ?? 0o755,
        isFile: () => false,
        isDirectory: () => true,
      };
    }
    throw new Error(`ENOENT: path not collected in snapshot: ${path}`);
  }
  /**
   * Tri-state permission answer: real facts for collected files and for
   * directories whose mode the probe recorded; 'unsupported' otherwise, so
   * permission checks skip instead of evaluating an invented mode (a guessed
   * 0o755 made every remote directory look group/world-readable).
   */
  async permissions(path: string): Promise<PermissionQuery> {
    // The probe is POSIX-only today, but guard anyway: a future win32
    // snapshot's mode field would be fake and must not be interpreted.
    if (this.platform === 'win32') return 'unsupported';
    const fileEntry = this.snapshot.files[path];
    if (fileEntry?.exists) return posixPermissionFacts(fileEntry.mode);
    const dirMode = this.snapshot.directoryModes?.[path];
    if (dirMode !== undefined) return posixPermissionFacts(dirMode);
    if (this.directoryExists(path) || this.hasChildPaths(path)) return 'unsupported';
    throw new Error(`ENOENT: path not collected in snapshot: ${path}`);
  }




  async ownership(path: string): Promise<{ uid: number; gid: number } | undefined> {
    const owner = this.snapshot.owners?.[path];
    return owner ? { uid: owner[0], gid: owner[1] } : undefined;
  }

  async privateGroups(): Promise<ReadonlyMap<number, number>> {
    return new Map(Object.entries(this.snapshot.privateGroups ?? {}).map(([gid, uid]) => [Number(gid), uid]));
  }

  async realpath(path: string): Promise<string> {
    // Snapshots don't resolve symlinks — return as-is if path exists
    if (await this.access(path)) return path;
    throw new Error(`ENOENT: path not collected in snapshot: ${path}`);
  }

  async readlink(path: string): Promise<string> {
    // Probes ≥ 1.0.1 record link targets for symlinks they meet; older
    // snapshots have none, and their entries are never marked as links.
    const target = this.snapshot.symlinks?.[path];
    if (target !== undefined) return target;
    throw new Error(`EINVAL: symlink target not collected in snapshot: ${path}`);
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

  hostname(): string {
    return this.snapshot.hostname;
  }

  getEnv(key: string): string | undefined {
    return this.snapshot.env?.[key];
  }

  get privilege() {
    return this.snapshot.privilege;
  }

  /** The probe ran as root (directly or via --sudo). */
  isPrivileged(): boolean {
    return this.snapshot.privilege?.isRoot === true;
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

    const symlinks = this.snapshot.symlinks ?? {};
    const entry = (filePath: string, isLink: boolean): DirentInfo => {
      const relative = filePath.slice(prefix.length);
      const name = relative.split('/').pop() || relative;
      const parentPath = filePath.slice(0, filePath.length - name.length - 1) || basePath;
      return isLink
        ? { name, isFile: false, isDirectory: false, isSymbolicLink: true, parentPath }
        : { name, isFile: true, isDirectory: false, parentPath };
    };

    for (const [filePath, file] of Object.entries(this.snapshot.files)) {
      if (!filePath.startsWith(prefix) || !file.exists) continue;
      results.push(entry(filePath, filePath in symlinks));
    }
    // Links to directories have no file entry; list them as links too
    for (const linkPath of Object.keys(symlinks)) {
      if (linkPath.startsWith(prefix) && !(linkPath in this.snapshot.files)) results.push(entry(linkPath, true));
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
