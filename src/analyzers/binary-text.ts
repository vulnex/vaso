/**
 * Text read from a file that is meant to be source code, telling a binary
 * (a Mach-O / ELF / PE executable, an archive) from source that merely
 * contains a NUL byte. A NUL in a comment does not stop Node or Python from
 * running a file, so one NUL must not hide it from analysis.
 */

/** Bytes inspected to decide whether a file is binary. */
const SNIFF = 8192;

/** Binaries are dense with NULs (headers, padding); source almost never has one. */
const BINARY_NUL_RATIO = 0.01;

export function looksBinary(text: string): boolean {
  const head = text.slice(0, SNIFF);
  if (head.startsWith('\x7fELF')) return true;
  let nuls = 0;
  for (let i = 0; i < head.length; i++) if (head.charCodeAt(i) === 0) nuls++;
  // a NUL next to bytes that aren't UTF-8 (read as U+FFFD): an executable
  // header (Mach-O cf fa ed fe, PE stubs) — source with a NUL is still UTF-8
  if (nuls > 0 && head.includes('\uFFFD')) return true;
  // over at least 512 bytes, so a short script with one NUL stays text
  return nuls > 0 && nuls / Math.max(head.length, 512) > BINARY_NUL_RATIO;
}

/**
 * The file's text ready to parse, or undefined for a binary. Stray NULs are
 * replaced by spaces, which keeps every offset and line number.
 */
export function sourceText(text: string): string | undefined {
  if (looksBinary(text)) return undefined;
  return text.includes('\0') ? text.replace(/\0/g, ' ') : text;
}
