import { join } from 'node:path';
import type { FSProvider } from '../core/fs-provider.js';

/**
 * Look for a binary under any nvm-managed Node version. nvm installs node
 * versions at ~/.nvm/versions/node/<version>/bin/, and npm globals land
 * there too — but those paths typically aren't on the non-interactive SSH
 * shell's PATH, so `which <bin>` misses them. We list version dirs, sort
 * descending (newest-first by string sort, which works for v-prefixed
 * semver in practice — v22.22.1 sorts after v18.20.0), and return the
 * first match.
 */
export async function findNvmBinary(home: string, fs: FSProvider, binaryName: string): Promise<string | undefined> {
  const nvmRoot = join(home, '.nvm', 'versions', 'node');
  let entries;
  try {
    entries = await fs.readdirEntries(nvmRoot);
  } catch {
    return undefined;
  }
  const versions = entries
    .filter(e => e.isDirectory)
    .map(e => e.name)
    .sort()
    .reverse();
  for (const v of versions) {
    const p = join(nvmRoot, v, 'bin', binaryName);
    if (await fs.access(p)) return p;
  }
  return undefined;
}

/**
 * Glob patterns that probe scanners should expand to surface nvm-installed
 * binaries on remote hosts. Used in adapters' getProbeManifest().
 */
export function nvmBinaryGlob(binaryName: string): string {
  return `~/.nvm/versions/node/*/bin/${binaryName}`;
}

/**
 * Glob patterns covering every well-known npm-global location for a
 * package.json. The probe expands these into actual file reads so VASO can
 * extract the package version even when `<bin> --version` fails over SSH
 * (no node on PATH, etc.). Returns the array as-is so adapters can spread
 * it into their probe manifest's globPatterns.
 */
export function npmPackageJsonGlobs(packageName: string): string[] {
  return [
    `~/.nvm/versions/node/*/lib/node_modules/${packageName}/package.json`,
    `~/.npm-global/lib/node_modules/${packageName}/package.json`,
    `~/.volta/tools/image/packages/${packageName}/package.json`,
    `/usr/local/lib/node_modules/${packageName}/package.json`,
    `/usr/lib/node_modules/${packageName}/package.json`,
    `/opt/homebrew/lib/node_modules/${packageName}/package.json`,
  ];
}
