/**
 * File names for per-host output (`--output-dir`, `--save-snapshot`).
 *
 * A file is named after the host's own hostname, which isn't unique across
 * targets: two users on one machine, or cloned VMs that all call themselves
 * `ubuntu`. The first target to claim a name gets `<hostname>`; another target
 * reporting the same hostname gets `<hostname>--<target label>` instead of
 * overwriting it.
 */

export function safeHostname(host: string): string {
  return host.replace(/[^A-Za-z0-9._-]/g, '_');
}

export class HostFileNames {
  /** file base name → target label that owns it */
  private owners = new Map<string, string>();

  /** The base name (no extension) for `hostname`, as seen on target `label`. */
  claim(hostname: string, label: string): string {
    const base = safeHostname(hostname);
    const owner = this.owners.get(base);
    if (owner === undefined || owner === label) {
      this.owners.set(base, label);
      return base;
    }
    const alt = `${base}--${safeHostname(label)}`;
    this.owners.set(alt, label);
    return alt;
  }
}
