import { join, basename, dirname, posix } from 'node:path';
import type { FSProvider, DirentInfo, ExecResult, ExecOptions, PermissionQuery } from './fs-provider.js';
import { posixPermissionFacts } from './permissions.js';
import type { ConfigTreeStatus, FileEntry, ProbeSnapshot } from './snapshot-types.js';
import type { Platform } from './types.js';

/** Most respellings recordedUnder tries for one path (MAX_LINK_HOPS in skill-root-scope.ts). */
const MAX_RESPELLINGS = 40;

/**
 * The link recorded for `path` under the spelling followed links gave its
 * directory (`spelled`: where a link leads → the link), when none is recorded
 * under `path` itself: its target and the key it is recorded under. Spellings
 * compose — a link inside a linked skill, or reached through a second linked
 * directory (`~/.claude/skills` → `~/.nix-profile/share/skills`,
 * `~/.nix-profile` → elsewhere), is recorded under the first link's spelling
 * only — so each respelling is tried in turn, a bounded number of times.
 */
function recordedUnder(
  symlinks: Readonly<Record<string, string>>,
  spelled: ReadonlyArray<[string, string]>,
  path: string,
): { target: string; key: string } | undefined {
  const pending = [path];
  const seen = new Set(pending);
  for (let tries = 0; pending.length > 0 && tries < MAX_RESPELLINGS; tries++) {
    const cur = pending.shift()!;
    for (let i = spelled.length - 1; i >= 0; i--) {
      const [real, link] = spelled[i];
      const rel = posix.relative(real, cur);
      if (rel === '' || rel === '..' || rel.startsWith('../') || posix.isAbsolute(rel)) continue;
      const key = posix.join(link, rel);
      const target = Object.hasOwn(symlinks, key) ? symlinks[key] : undefined;
      if (target !== undefined) return { target, key };
      if (!seen.has(key)) {
        seen.add(key);
        pending.push(key);
      }
    }
  }
  return undefined;
}

function stripTrailingSlash(name: string): string {
  return name.endsWith('/') ? name.slice(0, -1) : name;
}

/** A snapshot map's keys, sorted, with each key's position in the map. */
interface KeyIndex {
  keys: string[];
  order: number[];
}

type IndexedMap = 'files' | 'directories' | 'directoryModes' | 'symlinks';

export class SnapshotFSProvider implements FSProvider {
  readonly kind = 'snapshot' as const;
  readonly platform: Platform;
  private snapshot: ProbeSnapshot;
  private indexes = new Map<IndexedMap, KeyIndex>();

  constructor(snapshot: ProbeSnapshot) {
    this.snapshot = snapshot;
    this.platform = snapshot.platform as Platform;
  }

  async readFile(path: string): Promise<string> {
    const entry = this.snapshot.files[path];
    if (entry?.denied) throw deniedError(path);
    if (!entry || !entry.exists) {
      if (this.behindUnsearchable(path)) throw deniedError(path);
      throw new Error(`ENOENT: file not collected in snapshot: ${path}`);
    }
    if (entry.contentOmitted || typeof entry.content !== 'string') {
      // Present on the host, content deliberately not shipped (size cap,
      // budget, binary asset, metadata-only glob) — unreadable, not empty.
      throw omittedError(path, entry.omitted);
    }
    // Binary files arrive base64-encoded; decode as a local utf-8 read would
    return entry.encoding === 'base64' ? Buffer.from(entry.content, 'base64').toString('utf-8') : entry.content;
  }

  async readBytes(path: string): Promise<Uint8Array> {
    const entry = this.snapshot.files[path];
    if (!entry || !entry.exists) {
      if (this.behindUnsearchable(path)) throw deniedError(path);
      throw new Error(`ENOENT: file not collected in snapshot: ${path}`);
    }
    if (entry.contentOmitted || typeof entry.content !== 'string') {
      throw omittedError(path, entry.omitted);
    }
    // Probe ≥ 1.1.0 ships non-UTF-8 files base64-encoded, so their bytes are
    // exact. Text arrives as a UTF-8 string and re-encodes faithfully; from
    // older probes, invalid byte sequences were already replaced with U+FFFD.
    return entry.encoding === 'base64' ? Buffer.from(entry.content, 'base64') : Buffer.from(entry.content, 'utf-8');
  }

  async readHead(path: string, n: number): Promise<Uint8Array> {
    const entry = this.snapshot.files[path];
    if (entry?.exists && entry.contentOmitted && typeof entry.head === 'string') {
      return Buffer.from(entry.head, 'base64').subarray(0, n);
    }
    return (await this.readBytes(path)).slice(0, n);
  }

  async readdir(path: string): Promise<string[]> {
    const listing = this.snapshot.directories[path];
    if (listing) {
      // The Go probe appends '/' to directory entry names so callers can tell
      // dirs from files in a flat string list. We strip it here so consumers
      // get clean basenames usable for path.join() without producing '//'.
      return listing.map(stripTrailingSlash);
    }

    // A local readdir fails here even when files inside were read by name
    if (this.unlistable(path)) throw deniedError(path, 'scandir');
    if (this.behindUnsearchable(path)) throw deniedError(path, 'scandir');

    // Try to derive directory listing from collected files
    const entries = new Set<string>();
    const prefix = path.endsWith('/') ? path : path + '/';
    // Files the probe looked for but did not find are recorded with
    // exists: false — they must not appear in a synthesized listing.
    for (const filePath of this.keysUnder('files', prefix)) {
      if (this.snapshot.files[filePath].exists) {
        const relative = filePath.slice(prefix.length);
        const firstSegment = relative.split('/')[0];
        if (firstSegment) entries.add(firstSegment);
      }
    }
    const dirPaths = [
      ...this.keysUnder('directories', prefix),
      ...this.keysUnder('directoryModes', prefix),
      ...this.keysUnder('symlinks', prefix),
    ];
    for (const dirPath of dirPaths) {
      if (dirPath !== path) {
        const relative = dirPath.slice(prefix.length);
        const firstSegment = relative.split('/')[0];
        if (firstSegment) entries.add(firstSegment);
      }
    }

    if (entries.size > 0) return [...entries];
    // A directory the probe stat'ed but found nothing to collect in is empty
    if (this.snapshot.directoryModes?.[path] !== undefined) return [];
    throw new Error(`ENOENT: directory not collected in snapshot: ${path}`);
  }

  async readdirEntries(path: string, options?: { recursive?: boolean }): Promise<DirentInfo[]> {
    if (options?.recursive) {
      // Like a local walk: a directory that isn't there is an error, not empty
      if (!this.directoryExists(path) && !this.hasChildPaths(path)) {
        throw new Error(`ENOENT: directory not collected in snapshot: ${path}`);
      }
      if (this.unlistable(path) || this.behindUnsearchable(path)) throw deniedError(path, 'scandir');
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
      // A FIFO or device is neither a file nor a directory to a local readdir
      const entry = this.snapshot.files[fullPath];
      const isFile = entry?.exists === true && entry.omitted !== 'special';
      const isDir = rawDirs.has(name) || this.directoryExists(fullPath) || this.hasChildPaths(fullPath);
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
    if (this.behindUnsearchable(path)) return false;
    // Check if any collected path starts with this as a directory
    if (this.hasChildPaths(path)) return true;
    return false;
  }

  async stat(path: string): Promise<{ mode: number; isFile(): boolean; isDirectory(): boolean }> {
    const fileEntry = this.snapshot.files[path];
    // Denied at stat (inside an unreadable dir): the local stat fails too.
    // Denied only at open: the mode is known, the content isn't.
    if (fileEntry?.denied && !fileEntry.exists) throw deniedError(path, 'stat');
    if (fileEntry?.exists) {
      // A FIFO, socket or device (probe >= 1.3.1 says so) is not a regular
      // file, as a local stat reports it
      const special = fileEntry.omitted === 'special';
      return {
        mode: fileEntry.mode,
        isFile: () => !special,
        isDirectory: () => false,
      };
    }
    // Behind an unsearchable directory a local stat fails, even for a
    // directory the denied files under it imply
    if (!this.directoryExists(path) && this.behindUnsearchable(path)) throw deniedError(path, 'stat');
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
    if (!(await this.access(path)) && !(path in (this.snapshot.symlinks ?? {}))) {
      throw new Error(`ENOENT: path not collected in snapshot: ${path}`);
    }
    // …in the letters a case-insensitive filesystem stores, when the probe
    // recorded them (as a local realpath spells it). Other recorded
    // resolutions (a linked home) are for the skill-root scope only
    const real = this.resolveSymlinks(path);
    const recorded = this.resolvedDir(real);
    return recorded !== real && foldCase(recorded) === foldCase(real) ? recorded : real;
  }

  /**
   * Follows the link targets the probe recorded (≥ 1.1.0), component by
   * component like a local realpath — so an npm bin shim resolves into its
   * package and copies dedupe by what they point to. Links the probe never
   * met stay as they are (older snapshots have none).
   */
  private resolveSymlinks(path: string): string {
    const symlinks = this.snapshot.symlinks ?? {};
    let rest = posix.normalize(path).split('/').filter(Boolean);
    let current = '/';
    // Where each link followed so far leads → the spelling it was met by: a
    // tree walked through a link (`~/.claude/skills` → elsewhere) has its own
    // links recorded under that spelling only (`~/.claude/skills/x`)
    const spelled: Array<[real: string, link: string]> = [];
    for (let hops = 0; rest.length > 0;) {
      const next = posix.join(current, rest.shift()!);
      const hit = Object.hasOwn(symlinks, next) ? { target: symlinks[next], key: next } : recordedUnder(symlinks, spelled, next);
      if (hit === undefined) { current = next; continue; }
      const { target, key } = hit;
      if (++hops > 40) return path; // loop — give up like ELOOP, keep the path
      const resolved = posix.normalize(posix.isAbsolute(target) ? target : posix.join(posix.dirname(next), target));
      // under the spelling the link was recorded by, so spellings compose
      spelled.push([resolved, key]);
      rest = [...resolved.split('/').filter(Boolean), ...rest];
      current = '/';
    }
    return current;
  }

  async hardLinkOf(path: string): Promise<string | undefined> {
    return this.snapshot.files[path]?.hardLinkOf;
  }

  async readlink(path: string): Promise<string> {
    // Probes ≥ 1.1.0 record link targets for symlinks they meet; older
    // snapshots have none, and their entries are never marked as links.
    const target = this.snapshot.symlinks?.[path] ?? this.recordedThroughLink(path);
    if (target !== undefined) return target;
    throw new Error(`EINVAL: symlink target not collected in snapshot: ${path}`);
  }

  /** Where each recorded link leads (resolved) → the link, built on first use. */
  private linkTargets: Array<[real: string, link: string]> | undefined;

  /**
   * A link at `path` the probe recorded under the spelling a linked directory
   * above it gave (`~/.claude/skills/x` for `<elsewhere>/skills/x`, the tree
   * walked through `~/.claude/skills`).
   */
  private recordedThroughLink(path: string): string | undefined {
    const symlinks = this.snapshot.symlinks;
    if (!symlinks || !posix.isAbsolute(path)) return undefined;
    // where each link really leads (its whole chain followed: a relative
    // target recorded under a linked spelling is relative to the real directory)
    this.linkTargets ??= Object.keys(symlinks).map(link => [this.resolveSymlinks(link), link]);
    return recordedUnder(symlinks, this.linkTargets, posix.normalize(path))?.target;
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

  /** The probe was asked for this file: it has an entry, even when the file was absent. */
  collected(path: string): boolean {
    return Object.hasOwn(this.snapshot.files, path);
  }

  /** The names the probe listed in `dir` (directories end in `/`), if it listed it. */
  listing(dir: string): readonly string[] | undefined {
    return Object.hasOwn(this.snapshot.directories, dir) ? this.snapshot.directories[dir] : undefined;
  }

  /** The snapshot holds something below `dir` (a file, a listing or a link). */
  holdsUnder(dir: string): boolean {
    const prefix = dir.endsWith('/') ? dir : dir + '/';
    return this.hasChildPaths(dir) || this.keysUnder('symlinks', prefix).length > 0
      || this.keysUnder('directoryModes', prefix).length > 0;
  }

  /** The snapshot holds a file or a listing below `dir` — content of a tree,
   *  not just the names (and link targets) a listing of `dir` records. */
  holdsContentUnder(dir: string): boolean {
    return this.hasChildPaths(dir);
  }

  /**
   * `path` with its longest leading directory the probe recorded a resolution
   * for (a linked home, either spelling) replaced by where it resolves; as
   * is when none is recorded.
   */
  resolvedDir(path: string): string {
    const dirs = this.snapshot.resolvedDirs;
    if (!dirs) return path;
    for (let cur = path; ; cur = posix.dirname(cur)) {
      const real = Object.hasOwn(dirs, cur) ? dirs[cur] : undefined;
      if (real !== undefined) return cur === path ? real : posix.join(real, posix.relative(cur, path));
      if (posix.dirname(cur) === cur) return path;
    }
  }

  /** Names a config tree's wildcard segment matched in a home (`<dir>/<segment>` → names). */
  wildcardNames(): Readonly<Record<string, readonly string[]>> {
    return this.snapshot.wildcardNames ?? {};
  }

  /** Config-derived trees the probe walked, by literal base path, with what it did. */
  configTrees(): Readonly<Record<string, ConfigTreeStatus>> {
    return this.snapshot.configTrees ?? {};
  }

  /** The probe stopped following links in skills trees past its record bound. */
  skillLinksTruncated(): boolean {
    return this.snapshot.skillLinksTruncated === true;
  }

  get privilege() {
    return this.snapshot.privilege;
  }

  /** The probe ran as root (directly or via --sudo). */
  /**
   * A directory the probe saw but could not list: no read bit for anyone and
   * no listing (an unprivileged probe can't read a mode-000 directory, and
   * neither can a local scan by the same user).
   */
  private unlistable(path: string): boolean {
    const mode = this.snapshot.directoryModes?.[path];
    return mode !== undefined && (mode & 0o444) === 0 && !this.snapshot.directories[path] && !this.isPrivileged();
  }

  /** A directory the probe recorded without search (x) permission for anyone. */
  private unsearchable(path: string): boolean {
    const mode = this.snapshot.directoryModes?.[path];
    return mode !== undefined && (mode & 0o111) === 0 && !this.isPrivileged();
  }

  /**
   * Under a directory the probe recorded without search (x) permission: a
   * local stat or open of anything there fails with EACCES, existing or not,
   * so the snapshot answers the same instead of ENOENT.
   */
  private behindUnsearchable(path: string): boolean {
    if (this.isPrivileged()) return false;
    const modes = this.snapshot.directoryModes ?? {};
    for (let dir = dirname(path); dir !== dirname(dir); dir = dirname(dir)) {
      const mode = modes[dir];
      if (mode !== undefined && (mode & 0o111) === 0) return true;
    }
    return false;
  }

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
    // The probe records a mode only for directories it stat'ed successfully
    // (glob roots, ancestors), so an empty directory still exists remotely
    if (this.snapshot.directoryModes?.[path] !== undefined) return true;
    // Listed as a directory (trailing '/') in its parent's listing
    const parent = this.snapshot.directories[dirname(path)];
    if (Array.isArray(parent) && parent.includes(`${basename(path)}/`)) return true;
    if (!(path in this.snapshot.directories)) return false;
    const listing = this.snapshot.directories[path];
    return Array.isArray(listing);
  }

  /**
   * The keys of one snapshot map that start with prefix, in the map's own
   * order. A sorted index (built once) makes this a binary search: walking
   * every collected file per lookup cost seconds on a 10k-file snapshot.
   */
  private keysUnder(map: IndexedMap, prefix: string): string[] {
    let index = this.indexes.get(map);
    if (!index) {
      const all = Object.keys(this.snapshot[map] ?? {});
      const order = all.map((_, i) => i).sort((a, b) => (all[a] < all[b] ? -1 : all[a] > all[b] ? 1 : 0));
      index = { keys: order.map(i => all[i]), order };
      this.indexes.set(map, index);
    }
    const { keys, order } = index;
    let lo = 0;
    let hi = keys.length;
    while (lo < hi) {
      const mid = (lo + hi) >>> 1;
      if (keys[mid] < prefix) lo = mid + 1;
      else hi = mid;
    }
    const hits: number[] = [];
    for (let i = lo; i < keys.length && keys[i].startsWith(prefix); i++) hits.push(i);
    return hits.sort((a, b) => order[a] - order[b]).map(i => keys[i]);
  }

  private hasChildPaths(path: string): boolean {
    const prefix = path.endsWith('/') ? path : path + '/';
    // A file the probe was denied under this path proves the directory
    // exists — it is there, just unreadable (chmod 000), as a local scan sees it
    if (this.keysUnder('files', prefix).some(k => this.snapshot.files[k].exists || this.snapshot.files[k].denied)) return true;
    return this.keysUnder('directories', prefix).some(k => Array.isArray(this.snapshot.directories[k]));
  }

  private readdirRecursive(basePath: string): DirentInfo[] {
    const results: DirentInfo[] = [];
    const prefix = basePath.endsWith('/') ? basePath : basePath + '/';

    const symlinks = this.snapshot.symlinks ?? {};
    const entry = (filePath: string, isLink: boolean, special = false): DirentInfo => {
      const relative = filePath.slice(prefix.length);
      const name = relative.split('/').pop() || relative;
      const parentPath = filePath.slice(0, filePath.length - name.length - 1) || basePath;
      return isLink
        ? { name, isFile: false, isDirectory: false, isSymbolicLink: true, parentPath }
        // A FIFO or device (probe ≥ 1.3.1 says so) is no file to a local walk
        : { name, isFile: !special, isDirectory: false, parentPath };
    };

    // Like a local walk, never descend through a symlinked directory: the
    // probe collects what a skill link points to under the link's path
    // (walkSkillTree follows it explicitly), but a plain listing stops at it.
    const behindLink = (filePath: string): boolean => {
      const parts = filePath.slice(prefix.length).split('/');
      let current = basePath;
      for (const part of parts.slice(0, -1)) {
        current = posix.join(current, part);
        if (current in symlinks) return true;
      }
      return false;
    };

    for (const filePath of this.keysUnder('files', prefix)) {
      const file = this.snapshot.files[filePath];
      if (!file.exists || behindLink(filePath)) continue;
      results.push(entry(filePath, filePath in symlinks, file.omitted === 'special'));
    }
    // Links to directories have no file entry, and dangling or looping links
    // a non-existent one; a local listing shows them all as links
    for (const linkPath of this.keysUnder('symlinks', prefix)) {
      if (!this.snapshot.files[linkPath]?.exists && !behindLink(linkPath)) {
        results.push(entry(linkPath, true));
      }
    }
    // Directories hold no file entry, so the listing has none — except one
    // the probe could not list: a local walk lists it and skips its contents,
    // and the skill walk reports it (unlistableSubdirs in core/utils.ts)
    for (const dirPath of this.keysUnder('directoryModes', prefix)) {
      // (a link to one is listed as the link, above)
      if (dirPath === basePath || dirPath in symlinks || !this.unlistable(dirPath) || this.behindUnsearchable(dirPath) || behindLink(dirPath)) continue;
      const name = posix.basename(dirPath);
      results.push({ name, isFile: false, isDirectory: true, parentPath: posix.dirname(dirPath), denied: true });
    }
    // A folder that can be listed but not searched (mode 644): a local walk
    // lists its names, cannot read its files (EACCES) and cannot list its
    // folders. The probe (newer than 1.4.1) records its listing; the files
    // in it are denied entries without content, read here as EACCES.
    const listings = this.keysUnder('directories', prefix);
    if (Array.isArray(this.snapshot.directories[basePath])) listings.push(basePath);
    for (const dirPath of listings) {
      const listing = this.snapshot.directories[dirPath];
      if (!Array.isArray(listing) || !this.unsearchable(dirPath) || dirPath in symlinks
        || this.behindUnsearchable(dirPath) || (dirPath !== basePath && behindLink(`${dirPath}/x`))) continue;
      for (const raw of listing) {
        const isDir = raw.endsWith('/');
        const name = stripTrailingSlash(raw);
        const path = posix.join(dirPath, name);
        if (path in symlinks || this.snapshot.files[path]?.exists) continue; // listed above
        results.push(isDir
          ? { name, isFile: false, isDirectory: true, parentPath: dirPath, denied: true }
          : { name, isFile: true, isDirectory: false, parentPath: dirPath });
      }
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

    // A command naming a path (`codesign -dv /Applications/Muse.app`) is
    // answered only by its own output: a fuzzy match would hand it another
    // path's (another app's signature). Not collected = exit 127, not verified
    if (args.some(looksLikePath)) return undefined;

    // Try matching by command name and args pattern (manifest ids such as
    // `netstat-tcp`; a natural `cmd args` key is matched exactly above)
    for (const [id, output] of Object.entries(this.snapshot.commandOutputs)) {
      if (/\s/.test(id)) continue;
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

/**
 * `s` with full Unicode case folding and normalization applied, as a
 * case-insensitive volume compares names: `weiß` and `WEISS`, `ﬁx` and
 * `fix`, `.ſſh` and `.ssh`, `é` composed or not all fold alike.
 */
export function foldCase(s: string): string {
  return s.normalize('NFD').toLowerCase().toUpperCase().toLowerCase().normalize('NFD');
}

/** An argument naming a file or directory (absolute, home- or dot-relative, or with a slash). */
function looksLikePath(arg: string): boolean {
  return arg.includes('/') || arg.includes('\\') || arg.startsWith('~') || arg === '.' || arg === '..';
}

const OMITTED_WHY: Record<NonNullable<FileEntry['omitted']>, string> = {
  size: "larger than the probe's per-file limit",
  budget: "the probe's content budget ran out",
  asset: 'binary asset, recorded as metadata',
  metadata: 'recorded as metadata only',
  special: 'not a regular file',
  sensitive: 'reached through a link into a credential store, shell startup file or /etc, never shipped',
};

/** A file present on the host whose content the probe did not ship (`omitted` says why). */
function omittedError(path: string, reason: FileEntry['omitted']): Error & { omitted?: FileEntry['omitted'] } {
  const why = reason ? ` (${OMITTED_WHY[reason] ?? reason})` : '';
  return Object.assign(new Error(`content not collected in snapshot${why}: ${path}`), { omitted: reason });
}

/** The error a local read of a path behind an unreadable directory raises. */
function deniedError(path: string, syscall = 'open'): NodeJS.ErrnoException {
  // Worded like Node's own error so local and remote reports match
  const err: NodeJS.ErrnoException = new Error(`EACCES: permission denied, ${syscall} '${path}'`);
  err.code = 'EACCES';
  return err;
}
