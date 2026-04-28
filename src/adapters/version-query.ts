import { dirname, join } from 'node:path';
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
 */
export async function readPackageVersion(
  binary: string | undefined,
  fs: FSProvider,
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
  return undefined;
}
