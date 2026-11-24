/**
 * File names that aren't UTF-8 (Linux names are bytes: `\xfe.js`), held as
 * strings without loss — each byte that isn't part of a well-formed UTF-8
 * sequence becomes the lone surrogate U+DC00+byte (U+DC80–U+DCFF), as
 * Python's `surrogateescape` does. No UTF-8 name decodes to a lone
 * surrogate, so two names never share a string (decoding them to U+FFFD
 * made `\xfe.js` and `\xff.js` one file, and only one was read).
 *
 * The probe writes such names the same way (`\udcfe` in its JSON,
 * probe/fs_names.go), so a local and a remote scan list the same path.
 * Shared corpus: probe/testdata/fs-name-escapes.json.
 */

/** Length of the well-formed UTF-8 sequence at `i` (Unicode Table 3-7), 0 when there is none. */
function sequenceLength(b: Uint8Array, i: number): number {
  const c = b[i];
  if (c < 0x80) return 1;
  const cont = (k: number, lo = 0x80, hi = 0xbf) => i + k < b.length && b[i + k] >= lo && b[i + k] <= hi;
  if (c >= 0xc2 && c <= 0xdf) return cont(1) ? 2 : 0;
  if (c === 0xe0) return cont(1, 0xa0) && cont(2) ? 3 : 0;
  if ((c >= 0xe1 && c <= 0xec) || c === 0xee || c === 0xef) return cont(1) && cont(2) ? 3 : 0;
  if (c === 0xed) return cont(1, 0x80, 0x9f) && cont(2) ? 3 : 0;
  if (c === 0xf0) return cont(1, 0x90) && cont(2) && cont(3) ? 4 : 0;
  if (c >= 0xf1 && c <= 0xf3) return cont(1) && cont(2) && cont(3) ? 4 : 0;
  if (c === 0xf4) return cont(1, 0x80, 0x8f) && cont(2) && cont(3) ? 4 : 0;
  return 0;
}

/** A name's bytes as a string: UTF-8 decoded, every other byte as U+DC00+byte. */
export function decodeFsName(bytes: Uint8Array): string {
  const buf = Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let out = '';
  let start = 0; // start of the current well-formed run
  for (let i = 0; i < buf.length;) {
    const n = sequenceLength(buf, i);
    if (n > 0) {
      i += n;
      continue;
    }
    out += buf.toString('utf-8', start, i) + String.fromCharCode(0xdc00 + buf[i]);
    i += 1;
    start = i;
  }
  return out + buf.toString('utf-8', start);
}

/** Lone U+DC80–U+DCFF: a byte decodeFsName escaped (a low surrogate after a high one is half of a pair). */
const ESCAPED_BYTE = /(?<![\uD800-\uDBFF])[\uDC80-\uDCFF]/;

/** The string holds a byte decodeFsName escaped. */
export function hasEscapedBytes(path: string): boolean {
  return ESCAPED_BYTE.test(path);
}

/** The bytes of a path decodeFsName produced (its escaped bytes restored), undefined when it has none. */
export function encodeFsPath(path: string): Buffer | undefined {
  if (!hasEscapedBytes(path)) return undefined;
  const parts: Buffer[] = [];
  let start = 0;
  for (let i = 0; i < path.length; i++) {
    const u = path.charCodeAt(i);
    if (u >= 0xd800 && u <= 0xdbff) {
      const next = path.charCodeAt(i + 1);
      if (next >= 0xdc00 && next <= 0xdfff) i++; // a pair
      continue;
    }
    if (u >= 0xdc80 && u <= 0xdcff) {
      parts.push(Buffer.from(path.slice(start, i), 'utf-8'), Buffer.from([u - 0xdc00]));
      start = i + 1;
    }
  }
  parts.push(Buffer.from(path.slice(start), 'utf-8'));
  return Buffer.concat(parts);
}
