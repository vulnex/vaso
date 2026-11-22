import { createHash } from 'node:crypto';

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

/**
 * Longest file base name: file systems cap a name at 255 bytes, and the base
 * still gets a `--<label>` suffix and an extension.
 */
const MAX_BASE = 100;

/** A cut-down name that stays unique: its start plus a short hash of the whole. */
export function shortenFileBase(name: string): string {
  return name.length <= MAX_BASE ? name : `${name.slice(0, MAX_BASE - 13)}-${createHash('sha256').update(name).digest('hex').slice(0, 12)}`;
}

/** A hostname as a file base name: never empty, `.` or `..`, never too long for a file name. */
export function hostFileBase(host: string): string {
  const safe = safeHostname(host);
  return shortenFileBase(/^\.*$/.test(safe) ? `host${safe.replace(/\./g, '_')}` : safe);
}

export class HostFileNames {
  /** file base name (lower-cased) → target label that owns it */
  private owners = new Map<string, string>();

  /** The base name (no extension) for `hostname`, as seen on target `label`. */
  claim(hostname: string, label: string): string {
    const base = hostFileBase(hostname);
    const alt = `${base}--${shortenFileBase(safeHostname(label))}`;
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
