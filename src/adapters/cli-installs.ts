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
 * Primary = what PATH resolves (`which`; on remote scans the probe runs it
 * with user bin dirs prepended), else the newest discovered copy. Every other
 * copy with a different version is returned so advisory checks can evaluate it.
 */

/** Install dirs every CLI is looked for in, besides the adapter's own. */
const COMMON_SYSTEM_BIN_DIRS = ['/opt/homebrew/bin', '/usr/local/bin', '/usr/bin'];
const COMMON_USER_BIN_DIRS = ['.local/bin', '.npm-global/bin', '.volta/bin', '.bun/bin'];

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
  /** Also look in every nvm-managed Node version's bin dir (default true). */
  nvm?: boolean;
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

async function nvmBinDirs(home: string, fs: FSProvider): Promise<string[]> {
  const root = join(home, '.nvm', 'versions', 'node');
  try {
    const entries = await fs.readdirEntries(root);
    return entries
      .filter(e => e.isDirectory)
      .map(e => e.name)
      .sort((a, b) => compareVersions(b.replace(/^v/, ''), a.replace(/^v/, '')))
      .map(v => join(root, v, 'bin'));
  } catch {
    return [];
  }
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
    for (const dir of await nvmBinDirs(home, fs)) {
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
  if (found.length === 0) return { others: [] };

  const installs: CliInstall[] = [];
  for (const path of found) {
    // The PATH-resolved copy may always be run: on snapshots its `<name>
    // --version` output was collected for exactly that binary.
    const version = await spec.version(path, live || path === resolved);
    installs.push({ path, ...(version ? { version } : {}) });
  }

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
    `~/.nvm/versions/node/*/bin/${name}`,
    ...COMMON_USER_BIN_DIRS.map(d => `~/${d}/${name}`),
  ]);
}

/** Probe-manifest system paths for every copy of `name`. */
export function cliInstallSystemPaths(names: readonly string[]): string[] {
  return names.flatMap(name => COMMON_SYSTEM_BIN_DIRS.map(d => join(d, name)));
}
