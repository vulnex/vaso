import { open, constants as fsConstants } from 'node:fs/promises';

const MiB = (n: number) => `${(n / (1024 * 1024)).toFixed(n < 1024 * 1024 ? 2 : 0)} MiB`;

/** Size limits for files named on the command line, by kind. */
export const INPUT_LIMITS = {
  /** A YAML rule file (`--rules`, `rules validate`) or an inventory. */
  small: 4 * 1024 * 1024,
  /** A scan report (`visualize -i`) or a saved baseline. */
  report: 256 * 1024 * 1024,
} as const;

/**
 * Read a file the CLI was pointed at: a regular file only, at most `maxBytes`.
 * A FIFO would block the command forever and a device such as /dev/zero
 * never ends (and reports size 0). The file is opened non-blocking and
 * checked on the open handle, so a FIFO swapped in after a stat can't block
 * either. Errors keep the `code` of the underlying failure (ENOENT, EACCES)
 * or are EINVAL / EFBIG for a non-regular or oversized file.
 */
export async function readInputFile(path: string, maxBytes: number): Promise<string> {
  const handle = await open(path, fsConstants.O_RDONLY | (fsConstants.O_NONBLOCK ?? 0));
  try {
    const info = await handle.stat();
    if (info.isDirectory()) {
      throw Object.assign(new Error(`${path} is a directory`), { code: 'EISDIR' });
    }
    if (!info.isFile()) {
      throw Object.assign(new Error(`${path} is not a regular file`), { code: 'EINVAL' });
    }
    if (info.size > maxBytes) {
      throw Object.assign(new Error(`${path} is ${MiB(info.size)}, over the ${MiB(maxBytes)} limit`), { code: 'EFBIG' });
    }
    // The file may grow after the stat: never read past the limit
    const buf = Buffer.alloc(Math.min(info.size, maxBytes) + 1);
    let read = 0;
    while (read < buf.length) {
      const { bytesRead } = await handle.read(buf, read, buf.length - read, read);
      if (bytesRead === 0) break;
      read += bytesRead;
    }
    if (read > maxBytes) {
      throw Object.assign(new Error(`${path} is over the ${MiB(maxBytes)} limit`), { code: 'EFBIG' });
    }
    return buf.subarray(0, read).toString('utf-8');
  } finally {
    await handle.close();
  }
}
