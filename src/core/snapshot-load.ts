import { readFile, stat } from 'node:fs/promises';
import { isAbsolute } from 'node:path';
import type { ProbeSnapshot } from './snapshot-types.js';
import { MAX_REMOTE_OUTPUT_BYTES } from '../transport/ssh.js';

/**
 * Loading `--snapshot` files (scan, detect, probe validate). A snapshot is
 * untrusted input — it may be hand-edited or come from another machine — so
 * it is held to what a real probe can produce: the file no larger than a
 * remote probe run may stream, each file's content within the probe's
 * per-file cap (32 MiB for explicit configs, base64-inflated for binary
 * content), and all content within its 256 MiB budget. Past those limits a
 * scan would only exhaust memory.
 */

/** probe/collector.go maxConfigContentBytes (32 MiB), base64-encoded, rounded up. */
export const MAX_SNAPSHOT_FILE_CONTENT_CHARS = 48 * 1024 * 1024;
/** probe/collector.go maxTotalContentBytes (256 MiB, measured JSON-escaped). */
export const MAX_SNAPSHOT_TOTAL_CONTENT_CHARS = 256 * 1024 * 1024;

export class SnapshotLoadError extends Error {
  constructor(message: string, readonly problems: string[] = []) {
    super(message);
  }
}

const MiB = (n: number) => `${Math.round(n / 1024 / 1024)} MiB`;

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/** Permission bits as the probe records them (setuid/setgid/sticky included). */
function isMode(v: unknown): boolean {
  return Number.isInteger(v) && (v as number) >= 0 && (v as number) <= 0o7777;
}

/** Every problem that makes `value` unusable as a snapshot; empty when valid. */
export function validateSnapshot(value: unknown): string[] {
  if (!isRecord(value)) return ['Snapshot is not a JSON object'];
  const s = value;
  const errors: string[] = [];
  if (s.version !== 1) errors.push(`Unsupported snapshot version: ${String(s.version)}`);
  if (typeof s.platform !== 'string' || !s.platform) errors.push('Missing platform field');
  if (typeof s.hostname !== 'string' || !s.hostname) errors.push('Missing hostname field');
  // Adapters resolve every user path from it; without one detection runs blind
  if (typeof s.homedir !== 'string' || !isAbsolute(s.homedir)) errors.push('Missing or relative homedir field');

  if (!isRecord(s.files)) {
    errors.push('Missing or invalid files field');
  } else {
    let total = 0;
    let badEntries = 0;
    for (const [path, entry] of Object.entries(s.files)) {
      // A mode that isn't a permission number would read as 0 (owner-only)
      // and suppress every permission finding for the file
      if (!isRecord(entry) || (entry.content !== undefined && typeof entry.content !== 'string')
        || !isMode(entry.mode) || typeof entry.exists !== 'boolean') {
        badEntries++;
        continue;
      }
      const len = typeof entry.content === 'string' ? entry.content.length : 0;
      if (len > MAX_SNAPSHOT_FILE_CONTENT_CHARS) {
        errors.push(`File content of ${path} exceeds the probe's per-file limit (${MiB(len)} > ${MiB(MAX_SNAPSHOT_FILE_CONTENT_CHARS)})`);
      }
      total += len;
    }
    if (badEntries > 0) errors.push(`${badEntries} file entr${badEntries === 1 ? 'y is' : 'ies are'} not {content, mode, exists} objects`);
    if (total > MAX_SNAPSHOT_TOTAL_CONTENT_CHARS) {
      errors.push(`Total file content exceeds the probe's budget (${MiB(total)} > ${MiB(MAX_SNAPSHOT_TOTAL_CONTENT_CHARS)})`);
    }
  }
  if (!isRecord(s.directories)) errors.push('Missing or invalid directories field');
  if (s.directoryModes !== undefined
    && (!isRecord(s.directoryModes) || !Object.values(s.directoryModes).every(isMode))) {
    errors.push('Invalid directoryModes field (permission numbers expected)');
  }
  if (s.owners !== undefined && (!isRecord(s.owners) || !Object.values(s.owners).every(o =>
    Array.isArray(o) && o.length === 2 && o.every(id => Number.isInteger(id) && id >= 0)))) {
    errors.push('Invalid owners field ([uid, gid] pairs expected)');
  }
  if (!isRecord(s.commandOutputs)) errors.push('Missing or invalid commandOutputs field');
  if (s.env !== undefined && !isRecord(s.env)) errors.push('Invalid env field');
  if (s.probeVersion !== undefined && typeof s.probeVersion !== 'string') errors.push('Invalid probeVersion field (a version string expected)');
  if (s.privilege !== undefined) {
    const p = s.privilege;
    if (!isRecord(p) || typeof p.username !== 'string' || !Array.isArray(p.scannedUsers)
      || !p.scannedUsers.every(u => typeof u === 'string')) {
      errors.push('Invalid privilege field (needs username and scannedUsers[])');
    }
  }
  return errors;
}

/** Read, parse and validate a snapshot file; throws SnapshotLoadError. */
export async function loadSnapshotFile(path: string): Promise<ProbeSnapshot> {
  let raw: string;
  try {
    const size = (await stat(path)).size;
    if (size > MAX_REMOTE_OUTPUT_BYTES) {
      throw new SnapshotLoadError(`Snapshot file is ${MiB(size)}, larger than any probe run produces (${MiB(MAX_REMOTE_OUTPUT_BYTES)})`);
    }
    raw = await readFile(path, 'utf-8');
  } catch (err) {
    if (err instanceof SnapshotLoadError) throw err;
    const code = (err as NodeJS.ErrnoException).code;
    throw new SnapshotLoadError(code === 'ENOENT'
      ? `Snapshot file not found: ${path}`
      : `Failed to read snapshot file: ${(err as Error).message}`);
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    throw new SnapshotLoadError(`Snapshot file is not valid JSON: ${(err as Error).message}`);
  }

  const problems = validateSnapshot(parsed);
  if (problems.length > 0) throw new SnapshotLoadError('Invalid snapshot file:', problems);
  return parsed as ProbeSnapshot;
}

/** Lines to print for a SnapshotLoadError. */
export function snapshotErrorLines(err: SnapshotLoadError): string[] {
  return [err.message, ...err.problems.map(p => `  - ${p}`)];
}

/** Warning for a snapshot whose probe ran out of content budget (`truncated`). */
export const SNAPSHOT_TRUNCATED_WARNING =
  'vaso-probe content budget reached — some large agent/skill files were recorded as metadata only and not analysed';

/**
 * A warning when the snapshot came from a probe older than this CLI (or one
 * too old to record its version, < 1.3.1). New probe releases collect more —
 * denied entries, omit reasons, followed skill links — and a scan of an old
 * snapshot silently reports less. Dev builds and newer probes are fine.
 */
export function probeVersionWarning(snapshot: Pick<ProbeSnapshot, 'probeVersion'>, cliVersion: string): string | undefined {
  const cli = majorMinor(cliVersion);
  if (!cli) return undefined;
  if (!snapshot.probeVersion) {
    return `snapshot collected by a vaso-probe older than 1.3.1 — re-collect with the probe from VASO ${cliVersion} for full coverage`;
  }
  const probe = majorMinor(snapshot.probeVersion);
  if (!probe) return undefined; // dev / custom build
  if (probe[0] < cli[0] || (probe[0] === cli[0] && probe[1] < cli[1])) {
    return `snapshot collected by vaso-probe ${snapshot.probeVersion}, older than VASO ${cliVersion} — re-collect for full coverage`;
  }
  return undefined;
}

function majorMinor(v: string): [number, number] | undefined {
  const m = /^v?(\d+)\.(\d+)\./.exec(v.trim());
  return m ? [Number(m[1]), Number(m[2])] : undefined;
}
