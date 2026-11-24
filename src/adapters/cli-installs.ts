import { join } from 'node:path';
import type { FSProvider } from '../core/fs-provider.js';
import type { CliInstall } from '../core/types.js';
import { compareVersions, type VersionParseOptions } from '../core/semver.js';

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
/** Dirs an interactive shell's nvm-default Node bin is placed ahead of. */
const SYSTEM_BIN_DIRS = [...COMMON_SYSTEM_BIN_DIRS, '/bin', '/usr/sbin', '/snap/bin'];
const COMMON_USER_BIN_DIRS = [
  '.local/bin', '.npm-global/bin', '.volta/bin', '.bun/bin',
  // pnpm global bin (PNPM_HOME default on Linux / macOS)
  '.local/share/pnpm', 'Library/pnpm',
];

const VOLTA_PACKAGES = '.volta/tools/image/packages';

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
  { root: VOLTA_PACKAGES, binSubdir: 'bin' },
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
  /** How this CLI's versions order (OpenClaw's `-N` correction releases
   *  follow their base release). */
  versionOptions?: VersionParseOptions;
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
    let names = await listNames(base, fs);
    if (root === VOLTA_PACKAGES) {
      // Volta names each package image after the package, so a scoped one
      // nests: tools/image/packages/@github/copilot/bin (volta-layout v4
      // package_image_dir joins the full `@scope/name`).
      const scoped: string[] = [];
      for (const scope of names.filter(n => n.startsWith('@'))) {
        scoped.push(...(await listNames(join(base, scope), fs)).map(n => `${scope}/${n}`));
      }
      names = [...names.filter(n => !n.startsWith('@')), ...scoped];
    }
    names.sort((a, b) => compareVersions(b.replace(/^v/, ''), a.replace(/^v/, '')));
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

/**
 * Bin dir of nvm's default Node — what an interactive shell puts first on PATH
 * (nvm.sh prepends it). Resolves `~/.nvm/alias/default`: an exact version,
 * a prefix (`22` → newest installed v22.x), `node`/`stable` (newest), or
 * `lts/<name>` via `~/.nvm/alias/lts/`. `system` or unresolvable → undefined.
 */
export async function nvmDefaultBinDir(home: string, fs: FSProvider): Promise<string | undefined> {
  const nvmDir = join(home, '.nvm');
  const read = async (p: string): Promise<string | undefined> => {
    try { return (await fs.readFile(p)).trim() || undefined; } catch { return undefined; }
  };
  let alias = await read(join(nvmDir, 'alias', 'default'));
  for (let hops = 0; alias?.startsWith('lts/') && hops < 3; hops++) {
    alias = await read(join(nvmDir, 'alias', 'lts', alias.slice(4)));
  }
  if (!alias || alias === 'system') return undefined;
  const root = join(nvmDir, 'versions', 'node');
  const installed = (await listNames(root, fs)).filter(v => /^v\d/.test(v));
  const want = alias.replace(/^v/, '');
  const matches = alias === 'node' || alias === 'stable'
    ? installed
    : installed.filter(v => v.slice(1) === want || v.slice(1).startsWith(`${want}.`));
  if (matches.length === 0) return undefined;
  const newest = matches.sort((a, b) => compareVersions(b.slice(1), a.slice(1)))[0];
  return join(root, newest, 'bin');
}

/**
 * The PATH the remote probe resolves agent CLIs with (probe/collector.go
 * userBinDirs / systemBinDirs / buildAugmentedPath, kept equal by a guard
 * test): a login shell's user bin dirs ahead of the session PATH, then the
 * package-manager dirs a non-interactive session lacks. Local scans resolve
 * through the same PATH, so a scan from cron, CI or a non-interactive shell
 * names the same primary copy as a remote scan of that host.
 */
export const PROBE_USER_BIN_DIRS = [
  '.local/bin', '.bun/bin', '.cargo/bin', '.npm-global/bin', '.volta/bin',
  '.abacusai/bin', '.nvm/current/bin', '.claude/local', '.opencode/bin', 'bin',
];
export const PROBE_SYSTEM_BIN_DIRS = ['/opt/homebrew/bin', '/usr/local/bin', '/snap/bin'];

function augmentedPathDirs(home: string, fs: FSProvider): string[] {
  const userDirs = PROBE_USER_BIN_DIRS.map(d => join(home, d));
  const session = (fs.getEnv('PATH') ?? '').split(':').filter(Boolean);
  const missing = PROBE_SYSTEM_BIN_DIRS.filter(d => !session.includes(d));
  // As root, a bare name resolves to a system binary before any copy a user
  // planted in their own bin dir (same order as the probe)
  return (fs.isPrivileged?.() ?? false) ? [...session, ...missing, ...userDirs] : [...userDirs, ...session, ...missing];
}

function whichPath(name: string, home: string, fs: FSProvider): string | undefined {
  try {
    // A snapshot answers by name: the probe already ran `which` with this PATH
    const out = fs.execSync('which', [name], { timeout: 3000, path: augmentedPathDirs(home, fs).join(':') })
      .trim().split('\n')[0]?.trim();
    return out && out.startsWith('/') ? out : undefined;
  } catch {
    return undefined;
  }
}

/** Candidate paths in discovery order, PATH-resolved first. */
async function candidatePaths(home: string, fs: FSProvider, spec: CliInstallSpec): Promise<{ resolved?: string; onPath?: string; paths: string[] }> {
  const onPath = spec.names.map(n => whichPath(n, home, fs)).find(Boolean);
  let resolved = onPath;
  // A non-interactive PATH (cron, CI, the remote probe) lacks nvm, so `which`
  // can land on a system copy that interactive shells shadow: nvm.sh puts the
  // default Node's bin ahead of the system dirs. User dirs (~/.local/bin, …)
  // are often ahead of nvm, so only a system-dir hit is overridden.
  if (spec.nvm !== false && (!resolved || SYSTEM_BIN_DIRS.some(d => resolved!.startsWith(`${d}/`)))) {
    const defaultBin = await nvmDefaultBinDir(home, fs);
    for (const name of defaultBin ? spec.names : []) {
      const p = join(defaultBin!, name);
      if (await fs.access(p)) { resolved = p; break; }
    }
  }
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
  return { resolved, onPath, paths: [...new Set(paths)] };
}

export async function discoverCliInstalls(home: string, fs: FSProvider, spec: CliInstallSpec): Promise<CliInstalls> {
  const { resolved, onPath, paths } = await candidatePaths(home, fs, spec);
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
    // On snapshots only the copy `which` found may be "run": its `<name>
    // --version` output is the one the probe collected.
    const version = await spec.version(path, live || path === onPath);
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
    ?? newest(installs, spec.versionOptions)
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

function newest(installs: CliInstall[], opts?: VersionParseOptions): CliInstall | undefined {
  const versioned = installs.filter(i => i.version);
  if (versioned.length === 0) return undefined;
  return versioned.reduce((a, b) => (compareVersions(b.version!, a.version!, opts) > 0 ? b : a));
}

/**
 * Every existing copy of a CLI named `names` in the locations discovery
 * searches without running `which` — the common system and user bin dirs and
 * every Node version manager's per-version bin dirs — whatever its version.
 * `otherInstalls` keeps only copies at another version (one advisory finding
 * per version); deciding which programs are the agent's own (RUN-001/002)
 * needs all of them: a same-version nvm copy is often the package a wrapper
 * in ~/.local/bin and the agent's service run. The probe collects the same
 * locations (`cliInstallGlobs`, `cliInstallSystemPaths`).
 */
export async function cliCopyPaths(home: string, fs: FSProvider, names: readonly string[]): Promise<string[]> {
  const dirs = [...COMMON_SYSTEM_BIN_DIRS, ...COMMON_USER_BIN_DIRS.map(d => join(home, d)), ...(await nodeManagerBinDirs(home, fs))];
  const out: string[] = [];
  for (const dir of dirs) {
    for (const name of names) {
      const p = join(dir, name);
      try { if (await fs.access(p)) out.push(p); } catch {}
    }
  }
  return out;
}

/** Probe-manifest globs that surface every copy of `name` on a remote host. */
export function cliInstallGlobs(names: readonly string[]): string[] {
  return names.flatMap(name => [
    ...NODE_MANAGER_ROOTS.map(({ root, binSubdir }) =>
      `${root.startsWith('/') ? root : `~/${root}`}/*/${binSubdir}/${name}`),
    // Scoped Volta package images (`@scope/name`)
    `~/${VOLTA_PACKAGES}/@*/*/bin/${name}`,
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
    .filter(r => r.binSubdir.endsWith('bin') && r.root !== VOLTA_PACKAGES)
    .map(({ root, binSubdir }) => {
      const prefix = binSubdir === 'bin' ? '' : `/${binSubdir.slice(0, -'/bin'.length)}`;
      return `${root.startsWith('/') ? root : `~/${root}`}/*${prefix}/lib/node_modules/${packageName}/package.json`;
    });
}

/** Probe-manifest system paths for every copy of `name`. */
export function cliInstallSystemPaths(names: readonly string[]): string[] {
  return names.flatMap(name => COMMON_SYSTEM_BIN_DIRS.map(d => join(d, name)));
}
