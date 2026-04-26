import type { FSProvider } from '../core/fs-provider.js';

const SEMVER_RE = /(\d+\.\d+\.\d+(?:[-.][a-zA-Z0-9.]+)?)/;
const DEFAULT_TIMEOUT_MS = 3000;

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
