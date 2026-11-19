import { dirname, extname, join } from 'node:path';
import type { FSProvider } from '../core/fs-provider.js';
import { readCappedBytes, ScanLimitError } from '../core/file-limits.js';

/**
 * Telling a binary (a Mach-O / ELF / PE executable, an archive) from source
 * code, by intent. Any signature test can be forged by a polyglot — `MZ=1//`
 * is valid JavaScript, bash runs a script whose first line is junk bytes —
 * so a file an interpreter runs is always source: a script extension, or a
 * `#!` first line. Only other files are judged by their format signature,
 * on the raw bytes. Source keeps its NULs and non-UTF-8 bytes (Node runs a
 * script with either); NULs become spaces for the parsers.
 */

/** Extensions an interpreter runs (and the skill/MCP walkers treat as code). */
const SCRIPT_EXTENSIONS = new Set([
  '.js', '.mjs', '.cjs', '.ts', '.mts', '.cts', '.jsx', '.tsx',
  '.py', '.pyw',
  '.sh', '.bash', '.zsh', '.ksh', '.fish', '.command',
  '.ps1', '.psm1', '.bat', '.cmd',
  '.rb', '.pl', '.php', '.lua',
]);

/** Bytes read from the start of a file to judge its format (PE headers sit at e_lfanew). */
const HEAD_BYTES = 4096;

/** A file an interpreter runs: script extension or `#!` first line. Always source. */
export function isScriptFile(path: string, text: string): boolean {
  return SCRIPT_EXTENSIONS.has(extname(path).toLowerCase()) || text.startsWith('#!');
}

const startsWith = (b: Uint8Array, sig: number[], at = 0) => b.length >= at + sig.length && sig.every((x, i) => b[at + i] === x);
const u32le = (b: Uint8Array, at: number) => (b[at] | (b[at + 1] << 8) | (b[at + 2] << 16) | (b[at + 3] << 24)) >>> 0;
const ascii = (s: string) => [...s].map(c => c.charCodeAt(0));

/** binaryFormat's name for a macOS AppleDouble sidecar (magic 00 05 16 07). */
export const APPLEDOUBLE = 'AppleDouble metadata';

/** Entries an AppleDouble header lists at most (Finder writes two). */
const MAX_APPLEDOUBLE_ENTRIES = 64;
const u32be = (b: Uint8Array, at: number) => ((b[at] << 24) | (b[at + 1] << 16) | (b[at + 2] << 8) | b[at + 3]) >>> 0;

/**
 * An AppleDouble header (magic 00 05 16 07, version 1 or 2, 1 to
 * MAX_APPLEDOUBLE_ENTRIES entries) whose entry table fits in `b` and, given
 * the file's `size`, whose entries lie inside the file after the table.
 */
function appleDoubleHeader(b: Uint8Array, size?: number): boolean {
  if (!startsWith(b, [0x00, 0x05, 0x16, 0x07])) return false;
  if (!startsWith(b, [0x00, 0x02, 0x00, 0x00], 4) && !startsWith(b, [0x00, 0x01, 0x00, 0x00], 4)) return false;
  if (b.length < 26) return false;
  const n = (b[24] << 8) | b[25];
  const table = 26 + 12 * n;
  if (n < 1 || n > MAX_APPLEDOUBLE_ENTRIES || b.length < table) return false;
  if (size === undefined) return true;
  for (let i = 0; i < n; i++) {
    const offset = u32be(b, 26 + 12 * i + 4);
    const length = u32be(b, 26 + 12 * i + 8);
    if (offset < table || offset + length > size) return false;
  }
  return true;
}

/**
 * A macOS AppleDouble sidecar (`._index.js` beside `index.js`: the
 * original's Finder metadata and resource fork, never run or read by an
 * agent): a `._` name whose companion (`index.js`) is in the same folder,
 * holding a valid AppleDouble header (appleDoubleHeader), read from the
 * file's head. A `._setup.sh` with the magic but no companion, or a broken
 * header, is a file like any other — `sh` runs it past its first line.
 * listSkillTree also keeps one a file of the tree names.
 */
export async function isAppleDouble(fs: FSProvider, path: string, name: string): Promise<boolean> {
  if (!name.startsWith('._') || name.length === 2) return false;
  const head = await fs.readHead?.(path, 26 + 12 * MAX_APPLEDOUBLE_ENTRIES).catch(() => undefined);
  if (head === undefined || !appleDoubleHeader(head)) return false;
  if (!await fs.stat(join(dirname(path), name.slice(2))).then(() => true, () => false)) return false;
  // the entries against the file's size — unknown past the content-scan
  // limit (a snapshot holds no content then), where the table must do
  let size: number | undefined;
  try {
    size = (await readCappedBytes(fs, path)).byteLength;
  } catch (err) {
    if (!(err instanceof ScanLimitError)) return false;
  }
  return appleDoubleHeader(head, size);
}

/** Signatures checked on raw bytes. */
const SIGNATURES: Array<{ name: string; test: (b: Uint8Array) => boolean }> = [
  // ELF: class (32/64-bit) and data (LE/BE) bytes valid, version 1, and the
  // identification padding (bytes 9–15) zero — a text line forging the first
  // seven bytes runs as a script (the shell's no-binary fallback); one with
  // NULs in its first line does not
  {
    name: 'ELF executable',
    test: b => startsWith(b, [0x7f, 0x45, 0x4c, 0x46]) && (b[4] === 1 || b[4] === 2) && (b[5] === 1 || b[5] === 2) && b[6] === 1
      && startsWith(b, [0, 0, 0, 0, 0, 0, 0], 9),
  },
  // Mach-O thin (feedface / feedfacf, both byte orders) and fat (cafebabe / cafebabf / bebafeca)
  {
    name: 'Mach-O executable',
    test: b => [[0xfe, 0xed, 0xfa, 0xce], [0xfe, 0xed, 0xfa, 0xcf], [0xce, 0xfa, 0xed, 0xfe], [0xcf, 0xfa, 0xed, 0xfe],
      [0xca, 0xfe, 0xba, 0xbe], [0xca, 0xfe, 0xba, 0xbf], [0xbe, 0xba, 0xfe, 0xca]].some(sig => startsWith(b, sig)),
  },
  // PE: the MZ stub's e_lfanew points at a `PE\0\0` header
  { name: 'PE executable', test: b => startsWith(b, [0x4d, 0x5a]) && b.length >= 0x40 && startsWith(b, [0x50, 0x45, 0, 0], u32le(b, 0x3c)) },
  { name: 'WebAssembly module', test: b => startsWith(b, [0, 0x61, 0x73, 0x6d]) },
  { name: 'zip archive', test: b => [[0x50, 0x4b, 3, 4], [0x50, 0x4b, 5, 6], [0x50, 0x4b, 7, 8]].some(sig => startsWith(b, sig)) },
  { name: 'gzip archive', test: b => startsWith(b, [0x1f, 0x8b, 0x08]) },
  { name: 'bzip2 archive', test: b => startsWith(b, ascii('BZh')) && b[3] >= 0x31 && b[3] <= 0x39 && startsWith(b, [0x31, 0x41, 0x59, 0x26, 0x53, 0x59], 4) },
  { name: 'xz archive', test: b => startsWith(b, [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0]) },
  { name: 'zstd archive', test: b => startsWith(b, [0x28, 0xb5, 0x2f, 0xfd]) },
  { name: '7z archive', test: b => startsWith(b, [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c]) },
  { name: 'rar archive', test: b => startsWith(b, [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07]) },
  { name: 'SQLite database', test: b => startsWith(b, [...ascii('SQLite format 3'), 0]) },
  { name: 'PNG image', test: b => startsWith(b, [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]) },
  // macOS resource-fork sidecar (`._name`, written by Finder/tar on non-HFS volumes)
  { name: APPLEDOUBLE, test: b => appleDoubleHeader(b) },
];

/** The binary format raw leading bytes start with, or undefined. */
export function binaryFormat(head: Uint8Array): string | undefined {
  return SIGNATURES.find(s => s.test(head))?.name;
}

/**
 * The same from decoded text, when the raw bytes can't be had: only the
 * signatures made of bytes below 0x80 survive UTF-8 decoding, so the others
 * (Mach-O, PE's e_lfanew, gzip, …) never match — a U+FFFD is not a byte.
 */
function textBinaryFormat(text: string): string | undefined {
  // only the ASCII prefix: a signature can't extend past a decoded U+FFFD
  const head = text.slice(0, 64);
  const end = head.search(/[^\x00-\x7f]/);
  const prefix = end === -1 ? head : head.slice(0, end);
  const name = binaryFormat(Uint8Array.from(prefix, c => c.charCodeAt(0)));
  // the ones whose signature is all ASCII and needs no offset into the file
  return name && TEXT_SIGNATURES.has(name) ? name : undefined;
}

const TEXT_SIGNATURES = new Set(['ELF executable', 'WebAssembly module', 'zip archive', 'bzip2 archive', 'rar archive', 'SQLite database']);

/**
 * The binary format of a file read as `text`, or undefined when it is
 * source: never for a script (extension or shebang); otherwise judged on its
 * raw head when the provider can read one.
 */
export async function binaryFileFormat(fs: Pick<FSProvider, 'readHead'> & Partial<Pick<FSProvider, 'readBytes'>>, path: string,
  text: string): Promise<string | undefined> {
  // Markdown is read as text by the agent, never run: whatever its first bytes are
  if (MARKDOWN_EXTENSIONS.has(extname(path).toLowerCase())) return undefined;
  if (isScriptFile(path, text)) return pythonZipApp(fs, path, text);
  const head = await fs.readHead?.(path, HEAD_BYTES).catch(() => undefined);
  return head ? binaryFormat(head) : textBinaryFormat(text);
}

const MARKDOWN_EXTENSIONS = new Set(['.md', '.markdown', '.mdx']);

/**
 * Python runs a file holding a zip archive as a zipapp (its `__main__.py`),
 * whatever its extension and whatever text comes first: zipimport finds the
 * archive by the end-of-central-directory record in the file's last 64 KiB,
 * and takes it only when the central directory it points at is there.
 * Otherwise (the bytes `PK\x05\x06` in a comment) it runs the file as
 * source. A real zipapp's code is compressed, so it can't be read.
 */
async function pythonZipApp(fs: Partial<Pick<FSProvider, 'readBytes'>>, path: string, text: string): Promise<string | undefined> {
  const ext = extname(path).toLowerCase();
  const python = ext === '.py' || ext === '.pyw' || /^#![^\n]*python/.test(text);
  if (!python || !text.includes('PK\x05\x06')) return undefined;
  const bytes = await fs.readBytes?.(path).catch(() => undefined);
  // without the raw bytes, the decoded text (offsets are only approximate)
  return zipDirectory(bytes ?? Uint8Array.from(text, c => c.charCodeAt(0) & 0xff), bytes === undefined)
    ? 'zip archive (Python runs it as a zipapp)' : undefined;
}

/** Longest archive comment: the EOCD record sits in the last 64 KiB + 22 bytes. */
const MAX_ZIP_COMMENT = 0xffff;
const EOCD_SIZE = 22;

/**
 * Whether `b` ends with a zip archive zipimport accepts: the last
 * end-of-central-directory record in the file's tail, complete, with a
 * central directory size and offset that fit before it and a central
 * directory header (`PK\x01\x02`) where they point. `approximate`: offsets
 * from decoded text, where multi-byte characters shrank the file — only the
 * record and a header before it are required.
 */
function zipDirectory(b: Uint8Array, approximate: boolean): boolean {
  const from = Math.max(0, b.length - MAX_ZIP_COMMENT - EOCD_SIZE);
  let pos = -1;
  for (let i = b.length - 4; i >= from; i--) {
    if (b[i] === 0x50 && b[i + 1] === 0x4b && b[i + 2] === 5 && b[i + 3] === 6) { pos = i; break; }
  }
  if (pos < 0 || b.length - pos < EOCD_SIZE) return false;
  const size = u32le(b, pos + 12);
  const offset = u32le(b, pos + 16);
  if (size > pos || offset > pos) return false;
  const header = (at: number) => startsWith(b, [0x50, 0x4b, 1, 2], at);
  if (approximate) {
    for (let i = pos - 4; i >= 0; i--) if (header(i)) return true;
    return false;
  }
  const entries = b[pos + 10] | (b[pos + 11] << 8);
  return entries === 0 ? size === 0 : header(pos - size);
}

/** Source text ready to parse: stray NULs replaced by spaces, which keeps every offset and line number. */
export function sourceText(text: string): string {
  return text.includes('\0') ? text.replace(/\0/g, ' ') : text;
}
