/**
 * File names for per-host output (`--output-dir`, `--save-snapshot`).
 *
 * A file is named after the host's own hostname, which isn't unique across
 * targets: two users on one machine, or cloned VMs that all call themselves
 * `ubuntu` (or `Ubuntu` — the same file on a case-insensitive file system).
 * The first target to claim a name gets `<hostname>`; another target
 * reporting the same hostname gets `<hostname>--<target label>` instead of
 * overwriting it, numbered when even that is taken.
 */

export function safeHostname(host: string): string {
  return host.replace(/[^A-Za-z0-9._-]/g, '_');
}

/** A hostname as a file base name: never empty, `.` or `..`. */
export function hostFileBase(host: string): string {
  const safe = safeHostname(host);
  return /^\.*$/.test(safe) ? `host${safe.replace(/\./g, '_')}` : safe;
}

export class HostFileNames {
  /** file base name (lower-cased) → target label that owns it */
  private owners = new Map<string, string>();

  /** The base name (no extension) for `hostname`, as seen on target `label`. */
  claim(hostname: string, label: string): string {
    const base = hostFileBase(hostname);
    const alt = `${base}--${safeHostname(label)}`;
    for (let n = 0; ; n++) {
      const name = n === 0 ? base : n === 1 ? alt : `${alt}-${n}`;
      const key = name.toLowerCase();
      const owner = this.owners.get(key);
      if (owner === undefined || owner === label) {
        this.owners.set(key, label);
        return name;
      }
    }
  }
}
