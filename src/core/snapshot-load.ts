import { readFile, stat } from 'node:fs/promises';
import { isAbsolute, posix } from 'node:path';
import type { ProbeSnapshot } from './snapshot-types.js';
import { neutralizeSnapshotIdentity } from './snapshot-identity.js';
import { parseErrorMessage } from './parse-error.js';
import { escapeControlChars } from '../reporting/text-safety.js';

/**
 * A skill-tree file's head (probe ≥ 1.4.1): 4 KiB, or up to a PE stub's
 * e_lfanew (at most 1 MiB, as IOC-007 reads it) plus the PE header — base64.
 */
const MAX_HEAD_BASE64_CHARS = Math.ceil(((1 << 20) + 4) / 3) * 4;

/**
 * Loading `--snapshot` files (scan, detect, probe validate). A snapshot is
 * untrusted input — it may be hand-edited or come from another machine — so
 * it is held to what a real probe can produce: the file no larger than a
 * remote probe run may stream, each file's content within the probe's
 * per-file cap (32 MiB for explicit configs, base64-inflated for binary
 * content), and all content within its 256 MiB budget. Past those limits a
 * scan would only exhaust memory.
 */

/**
 * Largest probe output accepted, from a remote run or as a snapshot file. V8
 * strings cap near 512 MiB (0x1fffffe8 chars); decoding a larger buffer used
 * to crash the CLI outright. The probe budgets its own content (256 MiB) so
 * this is a backstop for older probes.
 */
export const MAX_REMOTE_OUTPUT_BYTES = 460 * 1024 * 1024;

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

/** `process.platform` values (core/types.ts Platform); the probe reports linux or darwin. */
const PLATFORMS = new Set(['aix', 'android', 'darwin', 'freebsd', 'haiku', 'linux', 'openbsd', 'sunos', 'win32', 'cygwin', 'netbsd']);

/** A record whose values are all strings. */
function isStringRecord(v: unknown): boolean {
  return isRecord(v) && Object.values(v).every(x => typeof x === 'string');
}

/** probe/config_roots.go maxConfigTrees: config-derived trees one snapshot records. */
export const MAX_CONFIG_TREES = 2000;
/** probe/config_roots.go maxWildcardNames: names one wildcardNames entry holds. */
const MAX_WILDCARD_NAMES = 1000;
/** Longest configTrees key accepted (PATH_MAX). */
const MAX_CONFIG_TREE_PATH = 4096;

/** A configTrees key: an absolute, normalized directory path (no `..`, no trailing slash, no NUL). */
function isConfigTreePath(k: string): boolean {
  return k.length > 0 && k.length <= MAX_CONFIG_TREE_PATH && k.startsWith('/') && !k.includes('\0')
    && posix.normalize(k) === k && (k === '/' || !k.endsWith('/'));
}

/** Every problem that makes `value` unusable as a snapshot; empty when valid. */
export function validateSnapshot(value: unknown): string[] {
  if (!isRecord(value)) return ['Snapshot is not a JSON object'];
  const s = value;
  const errors: string[] = [];
  if (s.version !== 1) {
    // a string "1" printed bare reads like the supported version
    const shown = typeof s.version === 'number' ? String(s.version) : (JSON.stringify(s.version) ?? 'missing').slice(0, 40);
    errors.push(`Unsupported snapshot version: ${shown} (expected the number 1)`);
  }
  if (typeof s.platform !== 'string' || !s.platform) errors.push('Missing platform field');
  // Checks branch on it, and it is printed: one of Node's platform names
  else if (!PLATFORMS.has(s.platform)) errors.push(`Unknown platform "${s.platform.slice(0, 40)}" (expected ${[...PLATFORMS].join(', ')})`);
  if (typeof s.hostname !== 'string' || !s.hostname) errors.push('Missing hostname field');
  // Adapters resolve every user path from it; without one detection runs blind
  if (typeof s.homedir !== 'string' || !isAbsolute(s.homedir)) errors.push('Missing or relative homedir field');
  else if (homeProblem(s.homedir)) errors.push(`Invalid homedir field: ${homeProblem(s.homedir)}`);

  if (!isRecord(s.files)) {
    errors.push('Missing or invalid files field');
  } else {
    let total = 0;
    let badEntries = 0;
    for (const [path, entry] of Object.entries(s.files)) {
      // A mode that isn't a permission number would read as 0 (owner-only)
      // and suppress every permission finding for the file
      if (!isRecord(entry) || (entry.content !== undefined && typeof entry.content !== 'string')
        || (entry.head !== undefined && (typeof entry.head !== 'string' || entry.head.length > MAX_HEAD_BASE64_CHARS))
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
  if (!isRecord(s.commandOutputs)) {
    errors.push('Missing or invalid commandOutputs field');
  } else {
    // Checks read stdout/stderr as text and branch on the exit status
    const bad = Object.values(s.commandOutputs).filter(o => !isRecord(o)
      || typeof o.stdout !== 'string' || typeof o.stderr !== 'string' || !Number.isInteger(o.exitCode)).length;
    if (bad > 0) errors.push(`${bad} commandOutputs entr${bad === 1 ? 'y is' : 'ies are'} not {stdout, stderr, exitCode} objects (text, text, integer)`);
  }
  if (s.env !== undefined && !isStringRecord(s.env)) errors.push('Invalid env field (string values expected)');
  if (s.symlinks !== undefined && !isStringRecord(s.symlinks)) errors.push('Invalid symlinks field (link targets expected)');
  if (s.configTrees !== undefined) {
    // Keys are literal directory paths, compared as such (probe-coverage.ts);
    // as many as the probe records at most (maxConfigTrees)
    const entries = isRecord(s.configTrees) ? Object.entries(s.configTrees) : undefined;
    if (!entries || !entries.every(([, v]) => v === 'collected' || v === 'refused' || v === 'limit')) {
      errors.push('Invalid configTrees field (collected, refused or limit expected)');
    } else if (entries.length > MAX_CONFIG_TREES) {
      errors.push(`Invalid configTrees field (more than ${MAX_CONFIG_TREES} trees)`);
    } else if (!entries.every(([k]) => isConfigTreePath(k))) {
      errors.push('Invalid configTrees field (normalized absolute directory paths expected)');
    }
  }
  if (s.resolvedDirs !== undefined) {
    const entries = isRecord(s.resolvedDirs) ? Object.entries(s.resolvedDirs) : undefined;
    if (!entries || !entries.every(([k, v]) => isConfigTreePath(k) && typeof v === 'string' && isConfigTreePath(v))) {
      errors.push('Invalid resolvedDirs field (normalized absolute directory paths expected)');
    } else if (entries.length > MAX_CONFIG_TREES) {
      errors.push(`Invalid resolvedDirs field (more than ${MAX_CONFIG_TREES} entries)`);
    }
  }
  if (s.wildcardNames !== undefined) {
    // probe/config_roots.go recordWildcardNames: names (no `/`), at most 1000 per directory
    const entries = isRecord(s.wildcardNames) ? Object.entries(s.wildcardNames) : undefined;
    if (!entries || !entries.every(([k, v]) => isConfigTreePath(k) && Array.isArray(v) && v.length <= MAX_WILDCARD_NAMES
      && v.every(n => typeof n === 'string' && n.length > 0 && n.length <= 255 && !n.includes('/') && !n.includes('\0')))) {
      errors.push('Invalid wildcardNames field (directory/segment keys with lists of names expected)');
    } else if (entries.length > MAX_CONFIG_TREES) {
      errors.push(`Invalid wildcardNames field (more than ${MAX_CONFIG_TREES} entries)`);
    }
  }
  if (s.timestamp !== undefined && typeof s.timestamp !== 'string') errors.push('Invalid timestamp field');
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
    const info = await stat(path);
    // A FIFO would block forever; a device such as /dev/zero reports size 0
    // and never ends
    if (!info.isFile()) throw new SnapshotLoadError(`Snapshot ${path} is not a regular file`);
    const size = info.size;
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

  return parseSnapshot(raw, 'Snapshot file');
}

/**
 * Parse and validate probe output — a snapshot file's text or what a remote
 * probe printed (the host may be hostile or compromised, so its output gets
 * the same checks as a file). `what` names the source in the error.
 */
export function parseSnapshot(raw: string, what: string): ProbeSnapshot {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    throw new SnapshotLoadError(`${what} is not valid JSON: ${parseErrorMessage(err)}`);
  }

  const problems = validateSnapshot(parsed);
  if (problems.length > 0) throw new SnapshotLoadError(`Invalid ${what.charAt(0).toLowerCase()}${what.slice(1)}:`, problems);
  const snapshot = parsed as ProbeSnapshot;
  // Adapters join user paths onto it and compare it with collected paths:
  // `/home/u/` or `/home/x/../u` would match none of them
  snapshot.homedir = normalizeHome(snapshot.homedir);
  return neutralizeSnapshotIdentity(snapshot);
}

/**
 * Why a home path can't be used: `/` (every user path would be a system
 * path) or `.`/`..` segments (`/home/u/../../..` — paths joined onto it
 * would resolve somewhere else than they read). A trailing or doubled slash
 * is only tidied (normalizeHome): $HOME can carry one.
 */
function homeProblem(home: string): string | undefined {
  if (!home.startsWith('/')) return undefined;
  if (home.split('/').some(seg => seg === '.' || seg === '..')) return 'has "." or ".." segments';
  if (posix.normalize(home) === '/') return 'is the filesystem root';
  return undefined;
}

/** An absolute home path without `.`/`..` segments or a trailing slash (POSIX or Windows-style). */
function normalizeHome(home: string): string {
  if (!home.startsWith('/')) return home;
  const normal = posix.normalize(home);
  return normal.length > 1 && normal.endsWith('/') ? normal.slice(0, -1) : normal;
}

/**
 * Lines to print for a SnapshotLoadError. A message can quote the file's own
 * bytes (a platform name, a JSON parse error): control characters are shown
 * escaped, never sent to the terminal.
 */
export function snapshotErrorLines(err: SnapshotLoadError): string[] {
  const show = (s: string) => escapeControlChars(s, { lineBreaks: true });
  return [show(err.message), ...err.problems.map(p => `  - ${show(p)}`)];
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
