import { isAbsolute, join, resolve } from 'node:path';

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
