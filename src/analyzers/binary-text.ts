import { extname } from 'node:path';
import type { FSProvider } from '../core/fs-provider.js';

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

/** Signatures checked on raw bytes. */
const SIGNATURES: Array<{ name: string; test: (b: Uint8Array) => boolean }> = [
  // ELF: class (32/64-bit) and data (LE/BE) bytes valid, version 1
  { name: 'ELF executable', test: b => startsWith(b, [0x7f, 0x45, 0x4c, 0x46]) && (b[4] === 1 || b[4] === 2) && (b[5] === 1 || b[5] === 2) && b[6] === 1 },
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
export async function binaryFileFormat(fs: Pick<FSProvider, 'readHead'>, path: string, text: string): Promise<string | undefined> {
  if (isScriptFile(path, text)) return pythonZipApp(path, text);
  const head = await fs.readHead?.(path, HEAD_BYTES).catch(() => undefined);
  return head ? binaryFormat(head) : textBinaryFormat(text);
}

/**
 * Python runs a file holding a zip archive as a zipapp (its `__main__.py`),
 * whatever its extension and whatever text comes first: it finds the archive
 * by the end-of-central-directory record, which survives UTF-8 decoding
 * (`PK\x05\x06`, all ASCII). Its code is compressed, so it can't be read.
 */
function pythonZipApp(path: string, text: string): string | undefined {
  const ext = extname(path).toLowerCase();
  const python = ext === '.py' || ext === '.pyw' || /^#![^\n]*python/.test(text);
  return python && text.includes('PK\x05\x06') ? 'zip archive (Python runs it as a zipapp)' : undefined;
}

/** Source text ready to parse: stray NULs replaced by spaces, which keeps every offset and line number. */
export function sourceText(text: string): string {
  return text.includes('\0') ? text.replace(/\0/g, ' ') : text;
}
