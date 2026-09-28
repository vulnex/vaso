import type { AgentInstallation } from '../../core/types.js';

export interface InstalledVersion {
  version: string;
  /** Path of a non-primary CLI copy; undefined for the installation's own version. */
  path?: string;
}

/**
 * Every version of the agent present on the host: the installation's own
 * version plus each other CLI copy (`otherInstalls`) with a known version.
 * Advisory checks evaluate all of them — an old copy that is still runnable
 * is exposed even when the one on PATH is current.
 */
export function installedVersions(installation: AgentInstallation): InstalledVersion[] {
  const out: InstalledVersion[] = [];
  const seen = new Set<string>();
  if (installation.version) {
    out.push({ version: installation.version });
    seen.add(installation.version);
  }
  for (const copy of installation.otherInstalls ?? []) {
    if (!copy.version || seen.has(copy.version)) continue;
    seen.add(copy.version);
    out.push({ version: copy.version, path: copy.path });
  }
  return out;
}

/** "v1.2.3" for the installation's own version, "v1.2.3 at /path" for another copy. */
export function describeVersion(v: InstalledVersion): string {
  return v.path ? `v${v.version} at ${v.path}` : `v${v.version}`;
}

/**
 * Subject for a result message: "openclaw v1.2.3", "openclaw v1.2.3 (and
 * v1.1.0 at /path)", or — when only other copies are affected — "an installed
 * openclaw copy (v1.1.0 at /path)".
 */
export function describeAffected(agent: string, affected: InstalledVersion[]): string {
  const primary = affected.find(v => !v.path);
  const copies = affected.filter(v => v.path);
  if (!primary) {
    return copies.length === 1
      ? `an installed ${agent} copy (${describeVersion(copies[0])})`
      : `${copies.length} installed ${agent} copies (${copies.map(describeVersion).join(', ')})`;
  }
  if (copies.length === 0) return `${agent} ${describeVersion(primary)}`;
  return `${agent} ${describeVersion(primary)} (and ${copies.map(describeVersion).join(', ')})`;
}
