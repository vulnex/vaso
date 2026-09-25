import { dirname, isAbsolute } from 'node:path';
import type { FSProvider, PermissionFacts, PermissionQuery } from './fs-provider.js';
import type { Evidence } from './types.js';

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

/**
 * Mark permission findings that other users cannot actually reach.
 *
 * A group/world-accessible file is only exposed if every ancestor directory
 * is traversable (x bit) by that same class: `~/Library` (0700) on macOS or
 * `/home/<user>` (0750) on Ubuntu blocks world access to everything beneath.
 * For each evidence item whose file grants group and/or world access, walk
 * the ancestors; when every class the file exposes is blocked by some
 * ancestor, set `mitigated` and name the blocking directory in `detail`.
 * Findings are downgraded (see `fromEvidence`), never dropped — the mode is
 * still wrong and becomes live if the parent is ever loosened.
 *
 * Unknown ancestors (stat errors, 'unsupported') count as traversable, so
 * remote/snapshot providers without ancestor data keep full severity.
 */
export async function markUnreachable(fs: FSProvider, evidence: Evidence[]): Promise<void> {
  const cache = new Map<string, PermissionFacts | undefined>();
  const factsOf = async (p: string): Promise<PermissionFacts | undefined> => {
    if (cache.has(p)) return cache.get(p);
    let facts: PermissionFacts | undefined;
    try {
      const q = await queryPermissions(fs, p);
      facts = q === 'unsupported' ? undefined : q;
    } catch {
      facts = undefined;
    }
    cache.set(p, facts);
    return facts;
  };

  for (const e of evidence) {
    if (!e.file || !isAbsolute(e.file)) continue;
    const facts = await factsOf(e.file);
    if (!facts) continue;
    const groupExposed = facts.groupRead || facts.groupWrite || facts.groupExec;
    const worldExposed = facts.worldRead || facts.worldWrite || facts.worldExec;
    if (!groupExposed && !worldExposed) continue;

    let groupBarrier: string | undefined;
    let worldBarrier: string | undefined;
    for (let dir = dirname(e.file); ; dir = dirname(dir)) {
      const a = await factsOf(dir);
      if (a) {
        if (!groupBarrier && !a.groupExec) groupBarrier = `${dir} (${a.octal})`;
        if (!worldBarrier && !a.worldExec) worldBarrier = `${dir} (${a.octal})`;
      }
      if (dirname(dir) === dir) break;
    }

    const groupBlocked = !groupExposed || groupBarrier !== undefined;
    const worldBlocked = !worldExposed || worldBarrier !== undefined;
    if (groupBlocked && worldBlocked) {
      e.mitigated = true;
      const barrier = worldBarrier ?? groupBarrier;
      e.detail = `${e.detail ? `${e.detail} — ` : ''}mitigated: not reachable by other users, parent ${barrier} blocks traversal`;
    } else if (worldExposed && worldBarrier) {
      e.detail = `${e.detail ? `${e.detail} — ` : ''}world access blocked by parent ${worldBarrier}; group access remains`;
    }
  }
}
