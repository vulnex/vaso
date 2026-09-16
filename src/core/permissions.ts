import type { FSProvider, PermissionFacts, PermissionQuery } from './fs-provider.js';

/**
 * Semantic permission queries for checks.
 *
 * Permission-based checks must not do POSIX mode math themselves: mode bits
 * are meaningless on win32 (`fs.stat` reports fake modes), and routing every
 * check through this module is what keeps them honest there. The tri-state
 * contract (facts | 'unsupported') means a platform the provider cannot
 * evaluate yields 'unsupported' — checks skip cleanly instead of reading
 * garbage bits (see the commercial design doc §3: Windows answers arrive via
 * a provider that implements `FSProvider.permissions()` with ACL evaluation,
 * not by making checks platform-neutral over fake modes).
 */

/** Derive semantic permission facts from a POSIX mode word. */
export function posixPermissionFacts(mode: number): PermissionFacts {
  const bits = mode & 0o777;
  const octal = bits.toString(8).padStart(3, '0');
  return {
    groupRead: (bits & 0o040) !== 0,
    groupWrite: (bits & 0o020) !== 0,
    groupExec: (bits & 0o010) !== 0,
    worldRead: (bits & 0o004) !== 0,
    worldWrite: (bits & 0o002) !== 0,
    worldExec: (bits & 0o001) !== 0,
    octal,
    description: `mode ${octal}`,
  };
}

/**
 * Query a path's permission facts through the provider.
 *
 * Preference order:
 *  1. The provider's own `permissions()` capability (a Windows ACL provider,
 *     or any provider that knows better than raw mode bits).
 *  2. `'unsupported'` on win32 — POSIX mode math must never run against
 *     win32's fake modes.
 *  3. POSIX mode bits from `stat()` everywhere else.
 *
 * Propagates `stat()` errors (ENOENT etc.) exactly like the direct
 * `fs.stat()` calls the checks used to make, so existing try/catch
 * flows are unchanged.
 */
export async function queryPermissions(fs: FSProvider, path: string): Promise<PermissionQuery> {
  if (fs.permissions) {
    return fs.permissions(path);
  }
  if (fs.platform === 'win32') {
    return 'unsupported';
  }
  const st = await fs.stat(path);
  return posixPermissionFacts(st.mode);
}

/** Group or world can read (POSIX `mode & 0o044`). */
export function readableByOthers(f: PermissionFacts): boolean {
  return f.groupRead || f.worldRead;
}

/** Group or world can write (POSIX `mode & 0o022`). */
export function writableByOthers(f: PermissionFacts): boolean {
  return f.groupWrite || f.worldWrite;
}

/** Any non-owner access at all (POSIX `mode & 0o077`) — i.e. NOT owner-only. */
export function accessibleByOthers(f: PermissionFacts): boolean {
  return (
    f.groupRead || f.groupWrite || f.groupExec ||
    f.worldRead || f.worldWrite || f.worldExec
  );
}
