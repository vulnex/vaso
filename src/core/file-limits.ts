import { stat } from 'node:fs/promises';
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
  constructor(readonly path: string) {
    super(`${path} exceeds the ${MAX_SCAN_FILE_BYTES}-byte scan limit`);
    this.name = 'ScanLimitError';
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
    return (await stat(path)).size > MAX_SCAN_FILE_BYTES;
  } catch {
    return false;
  }
}

function omittedFromSnapshot(fs: FSProvider, err: unknown): boolean {
  return fs.kind === 'snapshot' && err instanceof Error && err.message.includes('content not collected');
}

/** Read a file for content scanning; throws ScanLimitError when it exceeds MAX_SCAN_FILE_BYTES. */
export async function readCappedFile(fs: FSProvider, path: string): Promise<string> {
  if (await knownOverLimit(fs, path)) throw new ScanLimitError(path);
  let content: string;
  try {
    content = await fs.readFile(path);
  } catch (err) {
    if (omittedFromSnapshot(fs, err)) throw new ScanLimitError(path);
    throw err;
  }
  if (Buffer.byteLength(content, 'utf-8') > MAX_SCAN_FILE_BYTES) throw new ScanLimitError(path);
  return content;
}

/** readCappedFile for raw bytes (hashes, executable headers). */
export async function readCappedBytes(fs: FSProvider, path: string): Promise<Uint8Array> {
  if (await knownOverLimit(fs, path)) throw new ScanLimitError(path);
  let bytes: Uint8Array;
  try {
    bytes = await fs.readBytes(path);
  } catch (err) {
    if (omittedFromSnapshot(fs, err)) throw new ScanLimitError(path);
    throw err;
  }
  if (bytes.byteLength > MAX_SCAN_FILE_BYTES) throw new ScanLimitError(path);
  return bytes;
}
