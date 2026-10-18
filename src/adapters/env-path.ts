import { isAbsolute, join, resolve } from 'node:path';
import type { FSProvider } from '../core/fs-provider.js';

/**
 * A directory or file named by a relocation variable (CODEX_HOME,
 * CLAUDE_CONFIG_DIR, HERMES_HOME, …), as an absolute path: `~` expands to the
 * user's home and a relative value resolves against the working directory,
 * as the agent started from there would. Left relative, a scan and a fix
 * read and wrote a path relative to wherever vaso ran, and `vaso fix`
 * couldn't back it up (rollback then found nothing).
 */
export function envPath(value: string | undefined, userHome: string): string | undefined {
  const v = value?.trim();
  if (!v) return undefined;
  if (v === '~') return userHome;
  if (v.startsWith('~/')) return join(userHome, v.slice(2));
  return isAbsolute(v) ? v : resolve(v);
}

/** An XDG base directory variable: per the XDG spec a relative value is invalid and ignored. */
export function xdgPath(value: string | undefined): string | undefined {
  const v = value?.trim();
  return v && isAbsolute(v) ? v : undefined;
}

/**
 * Where an Electron app keeps its user data on Linux (app.getPath('appData')):
 * $XDG_CONFIG_HOME, else ~/.config. Only the scanning user's environment is
 * observable — another user's home falls back to ~/.config.
 */
export function linuxConfigHome(home: string, fs: FSProvider): string {
  const xdg = home === fs.homedir() ? xdgPath(fs.getEnv?.('XDG_CONFIG_HOME')) : undefined;
  return xdg ?? join(home, '.config');
}
