import { stat } from 'node:fs/promises';
import { encodeFsPath } from './fs-names.js';
import type { FSProvider } from './fs-provider.js';

/**
 * Largest file whose content is scanned — locally and by the remote probe
 * (probe/collector.go maxFileContentBytes), so a local and a remote scan of
 * the same host read the same files. Larger files are bundles or data dumps,
 * not hand-written code, config or skill docs.
 */
export const MAX_SCAN_FILE_BYTES = 5 * 1024 * 1024;

/**
 * A file not scanned because of the size limit. Locally the size decides; a
 * snapshot holds no content for such a file (the probe records it without
 * content), which reads the same way.
 */
export class ScanLimitError extends Error {
  /**
   * `size` — over MAX_SCAN_FILE_BYTES; `budget` — a snapshot whose probe ran
   * out of content budget before this file; `omitted` — a snapshot that holds
   * no content for it for another reason (binary asset, metadata only).
   */
  constructor(readonly path: string, readonly reason: 'size' | 'budget' | 'omitted' = 'size') {
    super(reason === 'size'
      ? `${path} exceeds the ${MAX_SCAN_FILE_BYTES}-byte scan limit`
      : `${path}: content not collected by the remote probe`);
    this.name = 'ScanLimitError';
  }

  /** Evidence detail for the skipped file. */
  get detail(): string {
    if (this.reason === 'budget') return "not scanned: the remote probe's content budget ran out before this file";
    if (this.reason === 'omitted') return 'not scanned: content not collected by the remote probe';
    return OVER_LIMIT_DETAIL;
  }
}

/** Evidence detail for a file skipped by the size limit. */
export const OVER_LIMIT_DETAIL = `not scanned: larger than the ${MAX_SCAN_FILE_BYTES / (1024 * 1024)} MiB content-scan limit`;

/**
 * Over the limit before reading: skills ship compiled binaries of 60 MB and
 * more (bun --compile), and every check would otherwise read each one whole
 * just to drop it. Only the local provider can answer without reading.
 */
async function knownOverLimit(fs: FSProvider, path: string): Promise<boolean> {
  if (fs.kind !== 'local') return false;
  try {
    return (await stat(encodeFsPath(path) ?? path)).size > MAX_SCAN_FILE_BYTES;
  } catch {
    return false;
  }
}

/** Why a snapshot holds no content for a file, when that is what `err` says. */
function omittedFromSnapshot(fs: FSProvider, err: unknown): ScanLimitError['reason'] | undefined {
  if (fs.kind !== 'snapshot' || !(err instanceof Error) || !err.message.includes('content not collected')) return undefined;
  if (err.message.includes('content budget')) return 'budget';
  if (err.message.includes('asset') || err.message.includes('metadata') || err.message.includes('regular file') || err.message.includes('never shipped')) return 'omitted';
  return 'size'; // the per-file cap — or a probe < 1.3.1, which doesn't say
}

/** Read a file for content scanning; throws ScanLimitError when it exceeds MAX_SCAN_FILE_BYTES. */
export async function readCappedFile(fs: FSProvider, path: string): Promise<string> {
  if (await knownOverLimit(fs, path)) throw new ScanLimitError(path);
  let content: string;
  try {
    content = await fs.readFile(path);
  } catch (err) {
    const reason = omittedFromSnapshot(fs, err);
    if (reason) throw new ScanLimitError(path, reason);
    throw err;
  }
  // The limit is on the bytes on disk: decoding turns each invalid UTF-8
  // byte into a 3-byte U+FFFD, so a 4 MiB file of such bytes decodes past it
  if (Buffer.byteLength(content, 'utf-8') > MAX_SCAN_FILE_BYTES && await bytesOnDisk(fs, path) > MAX_SCAN_FILE_BYTES) {
    throw new ScanLimitError(path);
  }
  return content;
}

/** The file's size in bytes as stored (a snapshot holds its bytes exactly, probe ≥ 1.1.0). */
async function bytesOnDisk(fs: FSProvider, path: string): Promise<number> {
  if (fs.kind === 'local') {
    try {
      return (await stat(encodeFsPath(path) ?? path)).size;
    } catch {
      return Infinity;
    }
  }
  try {
    return (await fs.readBytes(path)).byteLength;
  } catch {
    return Infinity;
  }
}

/** readCappedFile for raw bytes (hashes, executable headers). */
export async function readCappedBytes(fs: FSProvider, path: string): Promise<Uint8Array> {
  if (await knownOverLimit(fs, path)) throw new ScanLimitError(path);
  let bytes: Uint8Array;
  try {
    bytes = await fs.readBytes(path);
  } catch (err) {
    const reason = omittedFromSnapshot(fs, err);
    if (reason) throw new ScanLimitError(path, reason);
    throw err;
  }
  if (bytes.byteLength > MAX_SCAN_FILE_BYTES) throw new ScanLimitError(path);
  return bytes;
}
