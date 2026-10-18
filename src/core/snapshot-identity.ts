import type { ProbeSnapshot } from './snapshot-types.js';
import { escapeControlChars } from '../reporting/text-safety.js';

/**
 * The scanned host names itself in a snapshot (hostname, the probe user, the
 * users it scanned), and VASO prints those as they are — in warnings, the
 * "Scanning snapshot from host" line, report headers and host file names. A
 * hostile host (or a hand-made snapshot) can put terminal escapes there, so
 * they are neutralized once, where a snapshot enters the CLI.
 */
export function neutralizeSnapshotIdentity(snapshot: ProbeSnapshot): ProbeSnapshot {
  const clean = (s: string) => escapeControlChars(s, { lineBreaks: true });
  if (typeof snapshot.hostname === 'string') snapshot.hostname = clean(snapshot.hostname);
  const p = snapshot.privilege;
  if (p) {
    if (typeof p.username === 'string') p.username = clean(p.username);
    if (Array.isArray(p.scannedUsers)) p.scannedUsers = p.scannedUsers.map(u => (typeof u === 'string' ? clean(u) : u));
  }
  return snapshot;
}
