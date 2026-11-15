import { normalize } from 'node:path';

/**
 * Shared "overly broad trusted path" catalogue for workspace-trust checks
 * (CDX-006, GEM-011, GHC-009). Trusting one of these paths defeats the
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
  ];
}

export function expandHome(p: string, home: string): string {
  if (p === '~') return home;
  if (p.startsWith('~/')) return `${home}/${p.slice(2)}`;
  return p;
}

export function isBroadPath(rawPath: string, broadPaths: BroadPath[], home: string): BroadPath | undefined {
  const normalized = normalize(expandHome(rawPath, home));
  // normalize('/home/user/') → '/home/user', but normalize('/') stays '/'
  const trimmed = normalized.length > 1 && normalized.endsWith('/')
    ? normalized.slice(0, -1)
    : normalized;
  return broadPaths.find(b => trimmed === b.path);
}
