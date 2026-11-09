import { loadConfig, recordReadFailure, recordLoadError } from '../core/config-loader.js';
import type { FSProvider } from '../core/fs-provider.js';
import type { ParsedConfig } from '../core/types.js';

/** Whether something is at `path` — also when it can't be accessed (EACCES/EPERM), unlike `fs.access()`. */
export async function pathPresent(path: string, fs: FSProvider): Promise<boolean> {
  if (await fs.access(path)) return true;
  const code = await Promise.resolve().then(() => fs.stat(path)).then(
    () => undefined,
    (err: unknown) => (err as NodeJS.ErrnoException | null)?.code,
  );
  return code === 'EACCES' || code === 'EPERM';
}

/**
 * loadConfig for a config file that may not exist. `fs.access()` answers
 * false for a missing file and for one behind an unreadable (chmod 000)
 * directory alike; dropping the latter silently gave a clean 100 score. An
 * unreadable file goes through loadConfig, which records the read failure as
 * a CONFIG-LOAD finding; a missing one is skipped.
 */
export async function loadConfigIfPresent(filePath: string, fs: FSProvider): Promise<ParsedConfig | undefined> {
  if (!(await pathPresent(filePath, fs))) return undefined;
  try {
    return await loadConfig(filePath, fs);
  } catch {
    return undefined;
  }
}

/**
 * Text of a file an adapter or check reads itself (memory, rules and trust
 * files), or undefined when there is none. One that is there but can't be
 * read — unreadable, a directory, behind an unreadable directory — is
 * recorded as a CONFIG-LOAD finding (the engine captures failures during
 * checks too), not passed over as absent. A snapshot file whose content the
 * probe left out by design (metadata only, size caps) is not a failure: a
 * local scan reads it, and the two must agree.
 */
export async function readTextIfPresent(filePath: string, fs: FSProvider): Promise<string | undefined> {
  if (!(await pathPresent(filePath, fs))) return undefined;
  try {
    return await fs.readFile(filePath);
  } catch (err) {
    // Content the probe left out (metadata only, size or budget caps) reads
    // fine locally: not a failure. A FIFO or device ('special') fails a
    // local read too.
    if (err && typeof err === 'object' && 'omitted' in err && err.omitted !== 'special') return undefined;
    await recordReadFailure(filePath, fs, err);
    return undefined;
  }
}

/**
 * readTextIfPresent, parsed by `parse`. Content `parse` rejects (throws) is
 * recorded as a parse failure — a trust file the agent can't parse grants
 * nothing, but a scan that skips it silently reads as "checked, clean".
 */
export async function parseIfPresent<T>(filePath: string, fs: FSProvider, parse: (raw: string) => T): Promise<T | undefined> {
  const raw = await readTextIfPresent(filePath, fs);
  if (raw === undefined) return undefined;
  try {
    return parse(raw);
  } catch (err) {
    recordLoadError({ filePath, stage: 'parse', message: err instanceof Error ? err.message : String(err) });
    return undefined;
  }
}
