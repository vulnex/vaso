import { loadConfig } from '../core/config-loader.js';
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
