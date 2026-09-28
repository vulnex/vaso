import { join } from 'node:path';
import type { FSProvider } from '../core/fs-provider.js';
import type { CliInstall } from '../core/types.js';
import { compareVersions } from '../core/semver.js';

/**
 * Every copy of an agent CLI on a host, not just the first one found.
 *
 * Hosts routinely carry several copies of the same CLI — a Homebrew and a
 * /usr/local npm global, one per nvm Node version, a legacy global left behind
 * by a new installer — at different versions. Reporting only one hides old,
 * still-runnable (and possibly vulnerable) copies, and a fixed search order
 * reports whichever stale copy happens to sit in /usr/local/bin rather than
 * the one the user runs.
 *
 * Also covered: every Node version manager's per-version globals (nvm, fnm,
 * asdf, mise, volta, n), pnpm's global bin, and past versions a self-updating
 * installer keeps on disk (e.g. ~/.local/share/claude/versions/<ver>).
 *
 * Primary = what PATH resolves (`which`; on remote scans the probe runs it
 * with user bin dirs prepended), else the newest discovered copy. Every other
 * copy with a different version is returned so advisory checks can evaluate it.
 */

/** Install dirs every CLI is looked for in, besides the adapter's own. */
const COMMON_SYSTEM_BIN_DIRS = ['/opt/homebrew/bin', '/usr/local/bin', '/usr/bin'];
const COMMON_USER_BIN_DIRS = [
  '.local/bin', '.npm-global/bin', '.volta/bin', '.bun/bin',
  // pnpm global bin (PNPM_HOME default on Linux / macOS)
  '.local/share/pnpm', 'Library/pnpm',
];

/**
 * Per-version install roots of Node version managers: `<root>/<version>/<binSubdir>`
 * holds that version's npm globals. Roots starting with '/' are system-wide,
 * the rest are relative to $HOME.
 */
const NODE_MANAGER_ROOTS: ReadonlyArray<{ root: string; binSubdir: string }> = [
  { root: '.nvm/versions/node', binSubdir: 'bin' },
  { root: '.local/share/fnm/node-versions', binSubdir: 'installation/bin' },
  { root: 'Library/Application Support/fnm/node-versions', binSubdir: 'installation/bin' },
  { root: '.fnm/node-versions', binSubdir: 'installation/bin' },
  { root: '.asdf/installs/nodejs', binSubdir: 'bin' },
  { root: '.local/share/mise/installs/node', binSubdir: 'bin' },
  // Volta keeps each global package in its own image dir
  { root: '.volta/tools/image/packages', binSubdir: 'bin' },
  // tj/n (N_PREFIX defaults to /usr/local)
  { root: '/usr/local/n/versions/node', binSubdir: 'bin' },
];

/** A self-updating installer's store of past versions: `<dir>/<version>[/<binary>]`. */
export interface RetainedVersionsDir {
  /** Relative to $HOME; each entry is named after a version. */
  dir: string;
  /** Binary inside each version dir; omit when the entry itself is the binary. */
  binary?: string;
}

const VERSION_NAME_RE = /^v?\d+\.\d+(?:\.\d+)?(?:[-+.][0-9A-Za-z.-]+)?$/;

export interface CliInstallSpec {
  /** Binary names, preferred first (e.g. ['cursor-agent', 'agent']). */
  names: readonly string[];
  /** Absolute paths the adapter already knows about. */
  systemPaths?: readonly string[];
  /** Paths relative to $HOME the adapter already knows about. */
  userRelPaths?: readonly string[];
  /** A copy that is primary whenever it exists, overriding PATH order — for
   *  installers whose shim is authoritative even where a non-login PATH still
   *  finds a legacy copy first. */
  preferPath?: string;
  /** Also look in every Node version manager's per-version bin dirs — nvm,
   *  fnm, asdf, mise, volta, n (default true). */
  nvm?: boolean;
  /** Stores of past versions kept by the CLI's own updater. Every retained
   *  version is a copy; its version is the entry name (no exec). */
  retainedVersions?: readonly RetainedVersionsDir[];
  /** Also look in the common system/user bin dirs (default true). Off for
   *  names too generic to attribute (e.g. Cursor's `agent` shim). */
  commonDirs?: boolean;
  /**
   * Version of one copy. `canExec` is false when running that exact binary is
   * impossible (a remote snapshot only holds `<name> --version` for the
   * PATH-resolved copy); version it from files (package.json, build identity).
   */
  version(binary: string, canExec: boolean): Promise<string | undefined> | string | undefined;
}

export interface CliInstalls {
  /** The copy the user runs (PATH order), else the newest found. */
  primary?: CliInstall;
  /** Other copies whose version differs from the primary's (or is unknown). */
  others: CliInstall[];
}

async function listNames(dir: string, fs: FSProvider): Promise<string[]> {
  try {
    return (await fs.readdirEntries(dir)).map(e => e.name);
  } catch {
    return [];
  }
}

/** Every Node version manager's per-version bin dirs, newest version first per manager. */
async function nodeManagerBinDirs(home: string, fs: FSProvider): Promise<string[]> {
  const dirs: string[] = [];
  for (const { root, binSubdir } of NODE_MANAGER_ROOTS) {
    const base = root.startsWith('/') ? root : join(home, root);
    const names = (await listNames(base, fs))
      .sort((a, b) => compareVersions(b.replace(/^v/, ''), a.replace(/^v/, '')));
    dirs.push(...names.map(v => join(base, v, binSubdir)));
  }
  return dirs;
}

/** Retained past versions: path + version taken from the entry name. */
async function retainedCopies(home: string, fs: FSProvider, spec: CliInstallSpec): Promise<CliInstall[]> {
  const out: CliInstall[] = [];
  for (const { dir, binary } of spec.retainedVersions ?? []) {
    const base = join(home, dir);
    for (const name of await listNames(base, fs)) {
      if (!VERSION_NAME_RE.test(name)) continue; // `current`, `_download`, …
      const path = binary ? join(base, name, binary) : join(base, name);
      if (await fs.access(path)) out.push({ path, version: name.replace(/^v/, '') });
    }
  }
  return out;
}

function whichPath(name: string, fs: FSProvider): string | undefined {
  try {
    const out = fs.execSync('which', [name], { timeout: 3000 }).trim().split('\n')[0]?.trim();
    return out && out.startsWith('/') ? out : undefined;
  } catch {
    return undefined;
  }
}

/** Candidate paths in discovery order, PATH-resolved first. */
async function candidatePaths(home: string, fs: FSProvider, spec: CliInstallSpec): Promise<{ resolved?: string; paths: string[] }> {
  const resolved = spec.names.map(n => whichPath(n, fs)).find(Boolean);
  const paths: string[] = [];
  if (spec.preferPath) paths.push(spec.preferPath);
  if (resolved) paths.push(resolved);
  paths.push(...(spec.systemPaths ?? []));
  paths.push(...(spec.userRelPaths ?? []).map(rel => join(home, rel)));
  const primaryNames = spec.commonDirs === false ? [] : spec.names;
  for (const name of primaryNames) {
    paths.push(...COMMON_SYSTEM_BIN_DIRS.map(d => join(d, name)));
    paths.push(...COMMON_USER_BIN_DIRS.map(d => join(home, d, name)));
  }
  if (spec.nvm !== false) {
    for (const dir of await nodeManagerBinDirs(home, fs)) {
      for (const name of spec.names) paths.push(join(dir, name));
    }
  }
  return { resolved, paths: [...new Set(paths)] };
}

export async function discoverCliInstalls(home: string, fs: FSProvider, spec: CliInstallSpec): Promise<CliInstalls> {
  const { resolved, paths } = await candidatePaths(home, fs, spec);
  const live = fs.kind !== 'snapshot';

  // Existing copies, deduplicated by what they resolve to (symlinked shims,
  // merged /bin → /usr/bin).
  const seen = new Set<string>();
  const found: string[] = [];
  for (const p of paths) {
    if (p !== resolved && !(await fs.access(p))) continue;
    let real = p;
    try { real = await fs.realpath(p); } catch {}
    if (seen.has(real)) continue;
    seen.add(real);
    found.push(p);
  }
  const installs: CliInstall[] = [];
  for (const path of found) {
    // The PATH-resolved copy may always be run: on snapshots its `<name>
    // --version` output was collected for exactly that binary.
    const version = await spec.version(path, live || path === resolved);
    installs.push({ path, ...(version ? { version } : {}) });
  }
  // Past versions an updater keeps on disk: runnable by path, off PATH. The
  // active one usually is the primary's symlink target — deduped by realpath.
  for (const copy of await retainedCopies(home, fs, spec)) {
    let real = copy.path;
    try { real = await fs.realpath(copy.path); } catch {}
    if (seen.has(real)) continue;
    seen.add(real);
    installs.push(copy);
  }
  if (installs.length === 0) return { others: [] };

  const primary = (spec.preferPath ? installs.find(i => i.path === spec.preferPath) : undefined)
    ?? (resolved ? installs.find(i => i.path === resolved) : undefined)
    ?? newest(installs)
    ?? installs[0];
  // A snapshot can't version a non-PATH native binary (no exec, no symlink
  // targets to dedupe by), so an unversioned copy there is usually a second
  // link to the same install — and gives advisory checks nothing to evaluate.
  const others = installs.filter(i => i !== primary && (i.version ? i.version !== primary.version : live));
  // Several copies at one version are one finding, not several.
  const byVersion = new Map<string, CliInstall>();
  const distinct = others.filter(i => {
    if (!i.version) return true;
    if (byVersion.has(i.version)) return false;
    byVersion.set(i.version, i);
    return true;
  });
  return { primary, others: distinct };
}

function newest(installs: CliInstall[]): CliInstall | undefined {
  const versioned = installs.filter(i => i.version);
  if (versioned.length === 0) return undefined;
  return versioned.reduce((a, b) => (compareVersions(b.version!, a.version!) > 0 ? b : a));
}

/** Probe-manifest globs that surface every copy of `name` on a remote host. */
export function cliInstallGlobs(names: readonly string[]): string[] {
  return names.flatMap(name => [
    ...NODE_MANAGER_ROOTS.map(({ root, binSubdir }) =>
      `${root.startsWith('/') ? root : `~/${root}`}/*/${binSubdir}/${name}`),
    ...COMMON_USER_BIN_DIRS.map(d => `~/${d}/${name}`),
  ]);
}

/** Probe-manifest globs for an adapter's retained-version stores. */
export function retainedVersionGlobs(dirs: readonly RetainedVersionsDir[]): string[] {
  return dirs.map(({ dir, binary }) => (binary ? `~/${dir}/*/${binary}` : `~/${dir}/*`));
}

/** npm-global package.json locations under every Node version manager, so
 *  remote scans can version copies they cannot run. */
export function nodeManagerPackageJsonGlobs(packageName: string): string[] {
  return NODE_MANAGER_ROOTS
    .filter(r => r.binSubdir.endsWith('bin') && !r.root.includes('volta/tools/image/packages'))
    .map(({ root, binSubdir }) => {
      const prefix = binSubdir === 'bin' ? '' : `/${binSubdir.slice(0, -'/bin'.length)}`;
      return `${root.startsWith('/') ? root : `~/${root}`}/*${prefix}/lib/node_modules/${packageName}/package.json`;
    });
}

/** Probe-manifest system paths for every copy of `name`. */
export function cliInstallSystemPaths(names: readonly string[]): string[] {
  return names.flatMap(name => COMMON_SYSTEM_BIN_DIRS.map(d => join(d, name)));
}
