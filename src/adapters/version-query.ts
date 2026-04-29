import { basename, dirname, join } from 'node:path';
import type { FSProvider } from '../core/fs-provider.js';

const SEMVER_RE = /(\d+\.\d+\.\d+(?:[-.][a-zA-Z0-9.]+)?)/;
const DEFAULT_TIMEOUT_MS = 15000;

export interface QueryCliVersionOptions {
  /**
   * Argument sets to try in order. The first one that produces a SemVer-shaped
   * string wins. Defaults to `[['--version']]`. Use `[['version'], ['--version']]`
   * for binaries (hermes, openclaw) that accept either form.
   */
  argSets?: readonly (readonly string[])[];
  timeoutMs?: number;
}

export function queryCliVersion(
  binary: string | undefined,
  fs: FSProvider,
  options: QueryCliVersionOptions = {},
): string | undefined {
  if (!binary) return undefined;
  const argSets = options.argSets ?? [['--version']];
  const timeout = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;

  for (const args of argSets) {
    try {
      const output = fs.execSync(binary, [...args], { timeout }).trim();
      const m = SEMVER_RE.exec(output);
      if (m?.[1]) return m[1];
    } catch {}
  }
  return undefined;
}

/**
 * Read version from the package.json nearest to a CLI binary's resolved path.
 * Works for npm-installed binaries (global or local). Used as a fallback when
 * `<bin> --version` cannot run — typical over SSH snapshots where the bin is a
 * shim whose runtime (node, bun) isn't on the probe's PATH.
 *
 * Three-stage lookup, each succeeds in different environments:
 *   1. realpath + walk-up — works on local FS where the FSProvider can
 *      resolve the binary's symlink target.
 *   2. Direct npm-global lookup — when `npmPackageName` is provided, reads
 *      `<prefix>/lib/node_modules/<package>/package.json` directly. This is
 *      the snapshot-friendly path: no directory listing is needed, only a
 *      file read at a known location (which the probe must capture via a
 *      glob — see `npmPackageJsonGlobs`).
 *   3. Walk `<prefix>/lib/node_modules` looking for a package whose `bin`
 *      field references the binary's basename. Only works on local FS where
 *      `readdirEntries` is available.
 */
export async function readPackageVersion(
  binary: string | undefined,
  fs: FSProvider,
  npmPackageName?: string,
): Promise<string | undefined> {
  if (!binary) return undefined;
  try {
    let resolved: string;
    try {
      resolved = await fs.realpath(binary);
    } catch {
      resolved = binary;
    }
    let dir = dirname(resolved);
    for (let i = 0; i < 6; i++) {
      const pkgPath = join(dir, 'package.json');
      try {
        const raw = await fs.readFile(pkgPath);
        const pkg = JSON.parse(raw);
        if (pkg.version && SEMVER_RE.test(pkg.version)) {
          return pkg.version;
        }
      } catch {
        // No package.json here, walk up
      }
      const parent = dirname(dir);
      if (parent === dir) break;
      dir = parent;
    }
  } catch {
    // ignore
  }

  // Direct npm-global lookup (snapshot-safe; no directory listing required)
  if (npmPackageName) {
    const direct = await readNpmGlobalDirect(binary, fs, npmPackageName);
    if (direct) return direct;
  }

  // Fallback: walk node_modules looking for a matching `bin` (local-only)
  return readNpmGlobalPackageVersion(binary, fs);
}

/**
 * Direct path lookup at `<prefix>/lib/node_modules/<packageName>/package.json`,
 * where <prefix> is the parent of the binary's `bin/` directory. Works on
 * snapshot FS providers because it's a single file read, not a dir walk.
 */
async function readNpmGlobalDirect(
  binary: string,
  fs: FSProvider,
  packageName: string,
): Promise<string | undefined> {
  const binDir = dirname(binary);
  if (basename(binDir) !== 'bin') return undefined;
  const prefix = dirname(binDir);
  const pkgPath = join(prefix, 'lib', 'node_modules', packageName, 'package.json');
  try {
    const pkg = JSON.parse(await fs.readFile(pkgPath));
    if (pkg.version && SEMVER_RE.test(pkg.version)) return pkg.version;
  } catch {}
  return undefined;
}

/**
 * Walk `<prefix>/lib/node_modules/` looking for a package whose `bin` field
 * references the binary's basename. Handles scoped packages (`@scope/pkg`)
 * and both string-form (`"bin": "dist/cli.js"`) and object-form
 * (`"bin": {"gemini": "..."}`) bin declarations.
 */
async function readNpmGlobalPackageVersion(
  binary: string,
  fs: FSProvider,
): Promise<string | undefined> {
  const binDir = dirname(binary);
  if (basename(binDir) !== 'bin') return undefined;
  const name = basename(binary);
  const prefix = dirname(binDir);
  const nodeModulesDir = join(prefix, 'lib', 'node_modules');
  if (!(await fs.access(nodeModulesDir))) return undefined;

  let entries;
  try {
    entries = await fs.readdirEntries(nodeModulesDir);
  } catch {
    return undefined;
  }

  const candidates: string[] = [];
  for (const e of entries) {
    if (!e.isDirectory) continue;
    if (e.name.startsWith('@')) {
      const scopeDir = join(nodeModulesDir, e.name);
      let scoped;
      try {
        scoped = await fs.readdirEntries(scopeDir);
      } catch {
        continue;
      }
      for (const s of scoped) {
        if (s.isDirectory) candidates.push(join(scopeDir, s.name));
      }
    } else {
      candidates.push(join(nodeModulesDir, e.name));
    }
  }

  for (const pkgDir of candidates) {
    const pkgPath = join(pkgDir, 'package.json');
    let pkg;
    try {
      pkg = JSON.parse(await fs.readFile(pkgPath));
    } catch {
      continue;
    }
    if (!pkg.version || !SEMVER_RE.test(pkg.version)) continue;

    let matches = false;
    if (typeof pkg.bin === 'string') {
      // "bin": "..." — name defaults to package name (or its unscoped tail)
      const pkgName = typeof pkg.name === 'string' ? pkg.name : '';
      const tail = pkgName.includes('/') ? pkgName.split('/').pop()! : pkgName;
      matches = tail === name;
    } else if (pkg.bin && typeof pkg.bin === 'object') {
      matches = Object.prototype.hasOwnProperty.call(pkg.bin, name);
    }
    if (matches) return pkg.version;
  }
  return undefined;
}
