import { normalize } from 'node:path';

/**
 * Shared "overly broad trusted path" catalogue for workspace-trust and
 * path-permission checks (CDX-006, GEM-011, GHC-009, ABA-*, DEV-*, OPC-002, …).
 * A directory above the home always counts; with `ancestors`, so does a
 * directory above any catalogue entry. Trusting one of these paths defeats the
 * approval prompt for anything run inside it.
 */

export interface BroadPath {
  path: string;
  reason: string;
}

export function buildBroadPaths(home: string): BroadPath[] {
  return [
    { path: '/', reason: 'covers the entire filesystem' },
    { path: home, reason: 'covers the entire home directory' },
    { path: '/tmp', reason: 'is shared by all local users' },
    { path: '/var/tmp', reason: 'is shared by all local users' },
    { path: '/etc', reason: 'is the system configuration directory' },
    // macOS: /tmp, /var/tmp and /etc are links into /private
    { path: '/private/tmp', reason: 'is shared by all local users' },
    { path: '/private/var/tmp', reason: 'is shared by all local users' },
    { path: '/private/etc', reason: 'is the system configuration directory' },
  ];
}

export function expandHome(p: string, home: string): string {
  if (p === '~') return home;
  if (p.startsWith('~/')) return `${home}/${p.slice(2)}`;
  return p;
}

export interface BroadPathOptions {
  /**
   * The agent trusts a folder and everything below it (Gemini CLI
   * `isSubpath`, Copilot CLI "the files in, and below"), so a folder above
   * a broad path (`/Users`, `/home`, `/private`) is broad too.
   */
  ancestors?: boolean;
  /**
   * The agent compares paths case-insensitively (Gemini CLI `normalizePath`
   * and `isSubpath` lowercase both sides on darwin), so `/users` and
   * `/PRIVATE/TMP` match too.
   */
  ignoreCase?: boolean;
}

export function isBroadPath(rawPath: string, broadPaths: BroadPath[], home: string, opts: BroadPathOptions = {}): BroadPath | undefined {
  const key = (p: string): string => (opts.ignoreCase ? p.toLowerCase() : p);
  const normalized = normalize(expandHome(rawPath, home));
  const trimmed = normalized.length > 1 && normalized.endsWith('/')
    ? normalized.slice(0, -1)
    : normalized;
  const t = key(trimmed);
  const exact = broadPaths.find(b => t === key(b.path));
  if (exact) return exact;
  if (!trimmed.startsWith('/')) return undefined;
  if (opts.ancestors) {
    const below = broadPaths.find(b => b.path !== '/' && key(b.path).startsWith(`${t}/`));
    if (!below) return undefined;
    return {
      path: trimmed,
      reason: below.path === home
        ? `contains every home directory under it, ${home} included`
        : `contains ${below.path}, which ${below.reason}`,
    };
  }
  if (broadPaths.some(b => b.path === home) && t !== key(home) && key(home).startsWith(t === '/' ? '/' : `${t}/`)) {
    return { path: trimmed, reason: 'contains the home directory and every other user\'s' };
  }
  return undefined;
}
