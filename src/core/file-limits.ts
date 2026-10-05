import type { FSProvider } from './fs-provider.js';

/**
 * Largest file whose content is scanned — locally and by the remote probe
 * (probe/collector.go maxFileContentBytes), so a local and a remote scan of
 * the same host read the same files. Larger files are bundles or data dumps,
 * not hand-written code, config or skill docs.
 */
export const MAX_SCAN_FILE_BYTES = 5 * 1024 * 1024;

/** Read a file for content scanning; throws when it exceeds MAX_SCAN_FILE_BYTES. */
export async function readCappedFile(fs: FSProvider, path: string): Promise<string> {
  const content = await fs.readFile(path);
  if (Buffer.byteLength(content, 'utf-8') > MAX_SCAN_FILE_BYTES) {
    throw new Error(`${path} exceeds the ${MAX_SCAN_FILE_BYTES}-byte scan limit`);
  }
  return content;
}
