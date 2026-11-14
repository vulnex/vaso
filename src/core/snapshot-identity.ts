import type { ProbeSnapshot } from './snapshot-types.js';
import { escapeControlChars } from '../reporting/text-safety.js';

/**
 * The scanned host names itself in a snapshot (hostname, the probe user, the
 * users it scanned, its probe version and clock), and VASO prints those as
 * they are — in warnings, the "Scanning snapshot from host" line, `probe
 * validate`, report headers and host file names. A hostile host (or a
 * hand-made snapshot) can put terminal escapes there, so they are
 * neutralized once, where a snapshot enters the CLI. (The platform is
 * validated against Node's platform names instead.)
 */
export function neutralizeSnapshotIdentity(snapshot: ProbeSnapshot): ProbeSnapshot {
  const clean = (s: string) => escapeControlChars(s, { lineBreaks: true });
  if (typeof snapshot.hostname === 'string') snapshot.hostname = clean(snapshot.hostname);
  if (typeof snapshot.probeVersion === 'string') snapshot.probeVersion = clean(snapshot.probeVersion);
  if (typeof snapshot.timestamp === 'string') snapshot.timestamp = clean(snapshot.timestamp);
  const p = snapshot.privilege;
  if (p) {
    if (typeof p.username === 'string') p.username = clean(p.username);
    if (Array.isArray(p.scannedUsers)) p.scannedUsers = p.scannedUsers.map(u => (typeof u === 'string' ? clean(u) : u));
  }
  return snapshot;
}
