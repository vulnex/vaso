/**
 * The dependencies an MCP server ships with, for MCP-027's dependency arm
 * (advisories against the MCP SDK and other server-side packages).
 *
 * Read from the project around the server's entry file, most exact first:
 * the installed copy (`node_modules/<pkg>/package.json`, a `.venv`
 * dist-info), then the lockfile (package-lock.json, uv.lock, poetry.lock),
 * then the declared range (package.json `dependencies`, requirements*.txt,
 * pyproject.toml). Dev dependencies don't ship and are left out.
 */

import { dirname, join } from 'node:path';
import { parse as parseToml } from 'smol-toml';
import type { FSProvider } from '../core/fs-provider.js';
import { exactVersion } from '../core/version-range.js';

export interface ServerDependency {
  name: string;
  ecosystem: 'npm' | 'pypi';
  /** Exact version when known (installed or locked). */
  version?: string;
  /** Declared range when no exact version is known. */
  range?: string;
  /** File the version or range was read from. */
  source: string;
}

/** How far above the entry file to look for the project manifest. */
const MAX_PARENT_LEVELS = 3;

async function readJson(fs: FSProvider, path: string): Promise<Record<string, unknown> | undefined> {
  try {
    return JSON.parse(await fs.readFile(path)) as Record<string, unknown>;
  } catch {
    return undefined;
  }
}

async function readText(fs: FSProvider, path: string): Promise<string | undefined> {
  try {
    return await fs.readFile(path);
  } catch {
    return undefined;
  }
}

/** The entry file's directory and its parents, nearest first. */
function projectDirs(entryFile: string): string[] {
  const dirs: string[] = [];
  let dir = dirname(entryFile);
  for (let i = 0; i <= MAX_PARENT_LEVELS; i++) {
    dirs.push(dir);
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return dirs;
}

async function npmDependencies(dir: string, fs: FSProvider): Promise<ServerDependency[] | undefined> {
  const manifestPath = join(dir, 'package.json');
  const manifest = await readJson(fs, manifestPath);
  if (!manifest) return undefined;
  const declared = (manifest.dependencies ?? {}) as Record<string, unknown>;
  const lock = await readJson(fs, join(dir, 'package-lock.json'));
  const lockPackages = (lock?.packages ?? {}) as Record<string, { version?: string }>;
  const lockV1 = (lock?.dependencies ?? {}) as Record<string, { version?: string }>;

  const out: ServerDependency[] = [];
  for (const [name, spec] of Object.entries(declared)) {
    if (typeof spec !== 'string') continue;
    const installedPath = join(dir, 'node_modules', name, 'package.json');
    const installed = (await readJson(fs, installedPath))?.version;
    if (typeof installed === 'string') {
      out.push({ name, ecosystem: 'npm', version: installed, source: installedPath });
      continue;
    }
    const locked = lockPackages[`node_modules/${name}`]?.version ?? lockV1[name]?.version;
    if (typeof locked === 'string') {
      out.push({ name, ecosystem: 'npm', version: locked, source: join(dir, 'package-lock.json') });
      continue;
    }
    const exact = exactVersion(spec);
    out.push(exact
      ? { name, ecosystem: 'npm', version: exact, source: manifestPath }
      : { name, ecosystem: 'npm', range: spec, source: manifestPath });
  }
  return out;
}

/** PEP 503 name normalization: `MCP_Server` → `mcp-server`. */
function normalizePyName(name: string): string {
  return name.toLowerCase().replace(/[-_.]+/g, '-');
}

/** `mcp[cli]>=1.2,<2 ; python_version >= "3.10"` → name + version spec. */
function parseRequirement(line: string): { name: string; spec: string } | undefined {
  const req = line.split(/\s+#/)[0].split(';')[0].trim();
  const m = /^([A-Za-z0-9][\w.-]*)\s*(?:\[[^\]]*\])?\s*(.*)$/.exec(req);
  if (!m || req.startsWith('-')) return undefined;
  return { name: normalizePyName(m[1]), spec: m[2].trim() };
}

async function pythonLocked(dir: string, fs: FSProvider): Promise<Map<string, ServerDependency>> {
  const locked = new Map<string, ServerDependency>();
  // Installed into a project virtualenv: <name>-<version>.dist-info.
  for (const venv of ['.venv', 'venv']) {
    let libs: string[] = [];
    try {
      libs = await fs.readdir(join(dir, venv, 'lib'));
    } catch {
      continue;
    }
    for (const lib of libs) {
      const site = join(dir, venv, 'lib', lib, 'site-packages');
      let entries: string[] = [];
      try {
        entries = await fs.readdir(site);
      } catch {
        continue;
      }
      for (const entry of entries) {
        const m = /^(.+)-([^-]+)\.dist-info$/.exec(entry);
        if (m) locked.set(normalizePyName(m[1]), { name: normalizePyName(m[1]), ecosystem: 'pypi', version: m[2], source: join(site, entry) });
      }
    }
  }
  for (const lockName of ['uv.lock', 'poetry.lock']) {
    const raw = await readText(fs, join(dir, lockName));
    if (!raw) continue;
    try {
      const data = parseToml(raw) as { package?: Array<{ name?: string; version?: string }> };
      for (const pkg of data.package ?? []) {
        if (!pkg.name || !pkg.version) continue;
        const name = normalizePyName(pkg.name);
        if (!locked.has(name)) locked.set(name, { name, ecosystem: 'pypi', version: pkg.version, source: join(dir, lockName) });
      }
    } catch {
      // unparseable lockfile — fall back to declarations
    }
  }
  return locked;
}

async function pythonDependencies(dir: string, fs: FSProvider): Promise<ServerDependency[] | undefined> {
  const declared: Array<{ name: string; spec: string; source: string }> = [];

  let names: string[] = [];
  try {
    names = await fs.readdir(dir);
  } catch {
    return undefined;
  }
  for (const file of names.filter((n) => /^requirements.*\.txt$/i.test(n) && !/dev|test/i.test(n))) {
    const raw = await readText(fs, join(dir, file));
    for (const line of raw?.split('\n') ?? []) {
      const req = parseRequirement(line);
      if (req) declared.push({ ...req, source: join(dir, file) });
    }
  }
  const pyproject = await readText(fs, join(dir, 'pyproject.toml'));
  if (pyproject) {
    try {
      const data = parseToml(pyproject) as {
        project?: { dependencies?: string[] };
        tool?: { poetry?: { dependencies?: Record<string, unknown> } };
      };
      for (const dep of data.project?.dependencies ?? []) {
        const req = parseRequirement(dep);
        if (req) declared.push({ ...req, source: join(dir, 'pyproject.toml') });
      }
      for (const [name, value] of Object.entries(data.tool?.poetry?.dependencies ?? {})) {
        if (name === 'python') continue;
        const spec = typeof value === 'string' ? value : typeof (value as { version?: unknown })?.version === 'string' ? (value as { version: string }).version : '';
        declared.push({ name: normalizePyName(name), spec: poetryToPep440(spec), source: join(dir, 'pyproject.toml') });
      }
    } catch {
      // unparseable pyproject — ignore
    }
  }
  if (declared.length === 0) return undefined;

  const locked = await pythonLocked(dir, fs);
  const out: ServerDependency[] = [];
  const seen = new Set<string>();
  for (const dep of declared) {
    if (seen.has(dep.name)) continue;
    seen.add(dep.name);
    const exact = locked.get(dep.name);
    if (exact) {
      out.push(exact);
      continue;
    }
    const pinned = exactVersion(dep.spec);
    out.push(pinned
      ? { name: dep.name, ecosystem: 'pypi', version: pinned, source: dep.source }
      : { name: dep.name, ecosystem: 'pypi', range: dep.spec, source: dep.source });
  }
  return out;
}

/** Poetry `^1.2` / `~1.2` / `1.2.3` → a PEP 440 spec rangeBounds understands. */
function poetryToPep440(spec: string): string {
  const caret = /^\^\s*(\d+)(?:\.(\d+))?(?:\.(\d+))?$/.exec(spec.trim());
  if (caret) {
    const [, major, minor = '0', patch = '0'] = caret;
    const upper = Number(major) > 0 ? `${Number(major) + 1}.0.0` : `0.${Number(minor) + 1}.0`;
    return `>=${major}.${minor}.${patch},<${upper}`;
  }
  const tilde = /^~\s*(\d+)(?:\.(\d+))?(?:\.(\d+))?$/.exec(spec.trim());
  if (tilde) {
    const [, major, minor = '0', patch = '0'] = tilde;
    return `>=${major}.${minor}.${patch},<${major}.${Number(minor) + 1}.0`;
  }
  return /^\d/.test(spec.trim()) ? `==${spec.trim()}` : spec;
}

/**
 * Dependencies of the project a server entry file belongs to: the nearest
 * directory (the entry's own, or up to three parents) holding a manifest.
 */
export async function collectServerDependencies(
  entryFile: string,
  language: 'javascript' | 'python',
  fs: FSProvider,
  options: { searchParents?: boolean } = {},
): Promise<ServerDependency[]> {
  const dirs = options.searchParents === false ? [dirname(entryFile)] : projectDirs(entryFile);
  for (const dir of dirs) {
    const deps = language === 'python' ? await pythonDependencies(dir, fs) : await npmDependencies(dir, fs);
    if (deps) return deps;
  }
  return [];
}
