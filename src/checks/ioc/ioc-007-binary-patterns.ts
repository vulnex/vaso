import type { Evidence, ScanContext } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { getIOCDatabase } from '../../ioc/database.js';
import { skillFilesOf, skillsDirsOf, noSkillsDirResult } from '../skills/skill-files.js';
import { readCappedBytes, ScanLimitError } from '../../core/file-limits.js';
import { extname } from 'node:path';
import { binaryFormat, isScriptFile } from '../../analyzers/binary-text.js';

function bytesStartWith(haystack: Uint8Array, needle: Uint8Array): boolean {
  if (haystack.length < needle.length) return false;
  for (let i = 0; i < needle.length; i++) {
    if (haystack[i] !== needle[i]) return false;
  }
  return true;
}

/**
 * Two bytes are no PE header: `MZ=1//` starts a JavaScript file. An `MZ`
 * match needs the PE header its e_lfanew points at (binary-text.ts). A Java
 * class file also starts `cafebabe`; a universal Mach-O follows it with a
 * small architecture count where a class file has its version (≥ 45).
 */
function realHeader(name: string, head: Uint8Array): boolean {
  if (name === 'PE/DOS executable') return binaryFormat(head) === 'PE executable';
  // A script line forging `\x7fELF` without the identification padding runs as a script
  if (name === 'ELF binary') return binaryFormat(head) === 'ELF executable';
  if (name === 'Mach-O universal binary') {
    if (head.length < 8) return false;
    const archs = ((head[4] << 24) | (head[5] << 16) | (head[6] << 8) | head[7]) >>> 0;
    return archs >= 1 && archs <= 20;
  }
  return true;
}

/** Data files whose zero runs are their content: model weights, arrays, images, fonts, media, databases. */
const DATA_EXTENSIONS = new Set([
  '.bin', '.dat', '.data', '.raw', '.img', '.iso', '.npy', '.npz', '.pt', '.pth', '.ckpt', '.safetensors', '.onnx', '.gguf', '.ggml',
  '.h5', '.hdf5', '.tflite', '.pb', '.mlmodel', '.weights', '.model', '.parquet', '.arrow', '.feather', '.db', '.sqlite', '.idx',
  '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico', '.icns', '.tif', '.tiff', '.webp', '.psd',
  '.ttf', '.otf', '.woff', '.woff2', '.wav', '.mp3', '.ogg', '.flac', '.mp4', '.mov', '.webm', '.pdf',
]);

/** Machine code next to a zero run: a NOP sled, `syscall`, `int 0x80`, `xor eax,eax`, `/bin/sh`. */
const SHELLCODE_BYTES: number[][] = [
  [0x90, 0x90, 0x90, 0x90], [0x0f, 0x05], [0xcd, 0x80], [0x31, 0xc0], [0x48, 0x31, 0xc0], [0x48, 0x31, 0xff],
  [...'/bin/sh'].map(c => c.charCodeAt(0)),
];
/**
 * In a data file a two-byte opcode next to a zero run is chance (weights and
 * images hold millions of byte pairs), and so is a run of 0x90 alone (a
 * tensor filled with one value): only `/bin/sh`, or a NOP sled that leads into
 * machine code (dataShellcodeAt()), counts.
 */
const BIN_SH = [...'/bin/sh'].map(c => c.charCodeAt(0));
const MIN_SLED = 8;
/** Opcodes a sled leads into, within this many bytes of its end. */
const SLED_REACH = 16;

function matchesAt(bytes: Uint8Array, j: number, sig: number[]): boolean {
  return sig.every((x, k) => bytes[j + k] === x);
}

/**
 * `/bin/sh` at j, or a NOP sled at j followed shortly by a shellcode opcode.
 * A sled is walked once, from its start (or from the window's first byte, `from`).
 */
function dataShellcodeAt(bytes: Uint8Array, j: number, from: number): boolean {
  if (matchesAt(bytes, j, BIN_SH)) return true;
  if (bytes[j] !== 0x90 || (j > from && bytes[j - 1] === 0x90)) return false;
  let end = j;
  while (end < bytes.length && bytes[end] === 0x90) end++;
  if (end - j < MIN_SLED) return false;
  for (let k = end; k < Math.min(bytes.length, end + SLED_REACH); k++) {
    if (SHELLCODE_BYTES.some(sig => sig[0] !== 0x90 && matchesAt(bytes, k, sig))) return true;
  }
  return false;
}

/** Compiled code: zero runs next to machine code are what it is made of. */
const EXECUTABLE_FORMATS = new Set(['ELF executable', 'Mach-O executable', 'PE executable', 'WebAssembly module']);
const NEAR_RUN = 64;
const MAX_RUNS = 1000;

/**
 * Whether a run of 16+ NULs hides something. A run of zeros alone is not
 * shellcode — model weights, arrays and padded data are full of them. It is
 * suspicious inside a script (extension or shebang; Node runs one with NULs
 * in it, padded to get past readers), or in any other file next to
 * machine-code bytes. A data file (by extension or format signature) needs
 * an unmistakable payload next to the run; compiled executables never count.
 */
function nulPaddingSuspicious(file: string, bytes: Uint8Array, content: string, format: string | undefined): boolean {
  if (isScriptFile(file, content)) return true;
  if (format && EXECUTABLE_FORMATS.has(format)) return false;
  if (bytes.every(b => b === 0)) return false;
  const data = Boolean(format) || DATA_EXTENSIONS.has(extname(file).toLowerCase());
  const shellcodeAt = data
    ? (j: number, from: number) => dataShellcodeAt(bytes, j, from)
    : (j: number) => SHELLCODE_BYTES.some(sig => matchesAt(bytes, j, sig));
  let runs = 0;
  for (let i = 0; i < bytes.length && runs < MAX_RUNS; i++) {
    if (bytes[i] !== 0) continue;
    let end = i;
    while (end < bytes.length && bytes[end] === 0) end++;
    if (end - i >= 16) {
      runs++;
      // the bytes just before and just after the run
      for (const [from, to] of [[Math.max(0, i - NEAR_RUN), i], [end, Math.min(bytes.length, end + NEAR_RUN)]]) {
        for (let j = from; j < to; j++) {
          if (shellcodeAt(j, from)) return true;
        }
      }
    }
    i = end;
  }
  return false;
}

/** Bytes read from a file too large to scan whole: enough for a PE stub's e_lfanew to land inside. */
const HEAD_BYTES = 4096;
/** e_lfanew beyond this is no real PE stub. */
const MAX_PE_OFFSET = 1 << 20;

/**
 * The head of a file too large to scan whole. A PE header sits where the MZ
 * stub's e_lfanew points (usually 0x80–0x118, sometimes past 4 KiB): read up
 * to it.
 */
async function readFileHead(fs: ScanContext['fs'], file: string): Promise<Uint8Array | undefined> {
  const head = await fs.readHead?.(file, HEAD_BYTES).catch(() => undefined);
  if (!head || head.length < 0x40 || head[0] !== 0x4d || head[1] !== 0x5a) return head;
  const peOffset = (head[0x3c] | (head[0x3d] << 8) | (head[0x3e] << 16) | (head[0x3f] << 24)) >>> 0;
  if (peOffset + 4 <= head.length || peOffset > MAX_PE_OFFSET) return head;
  return (await fs.readHead?.(file, peOffset + 4).catch(() => undefined)) ?? head;
}

export const ioc007 = defineCheck({
  id: 'IOC-007',
  name: 'Binary Pattern Match',
  category: 'ioc',
  severity: 'critical',
  description: 'YARA-like byte/regex patterns on skill files (ELF/MachO/PE headers anchored at offset 0; shellcode / packed JS via regex)',

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    const noDir = noSkillsDirResult(ctx, h);
    if (noDir) return noDir;

    const db = getIOCDatabase();
    const files = await skillFilesOf(ctx);
    const bufferPatterns = db.binaryPatterns.filter(bp => bp.type === 'buffer');
    let payloadMatch = false;

    for (const file of files) {
      let matched: { name: string } | undefined;
      let bytes: Uint8Array | undefined;
      try {
        bytes = await readCappedBytes(ctx.fs, file);
      } catch (err) {
        if (!(err instanceof ScanLimitError)) continue;
        // A large native helper is exactly what this check is for. Its
        // header is in the first bytes, whatever the size: judge that, and
        // only say "not scanned" when even the header can't be read.
        const head = await readFileHead(ctx.fs, file);
        const format = head && bufferPatterns.find(bp => bytesStartWith(head, bp.pattern as Uint8Array) && realHeader(bp.name, head));
        if (format) {
          evidence.push({ file, detail: `Compiled executable (${format.name}) — its code can't be reviewed or analysed (too large to scan beyond its header)` });
        } else if (!head) {
          evidence.push({ file, detail: err.detail, mitigated: true });
        }
        continue;
      }

      // Buffer patterns represent executable magic bytes and must match at
      // file offset 0. Reading the file as bytes lets us avoid the latin1
      // substring search, which used to match the 2-byte PE magic ("MZ")
      // anywhere in the file — including inside identifiers like "xMZx".
      const format = binaryFormat(bytes);
      if (bufferPatterns.length > 0) {
        for (const bp of bufferPatterns) {
          if (bytesStartWith(bytes, bp.pattern as Uint8Array) && realHeader(bp.name, bytes)) {
            matched = { name: bp.name };
            break;
          }
        }
      }

      // Regex patterns operate on file text (e.g. packed-JS wrappers).
      if (!matched) {
        const regexPatterns = db.binaryPatterns.filter(bp => bp.type === 'regex');
        if (regexPatterns.length > 0) {
          const content = Buffer.from(bytes).toString('utf-8');
          for (const bp of regexPatterns) {
            if ((bp.pattern as RegExp).test(content)) {
              if (bp.name === 'NUL-padding shellcode' && !nulPaddingSuspicious(file, bytes, content, format)) continue;
              matched = { name: bp.name };
              break;
            }
          }
        }
      }

      if (matched) {
        const formatOnly = bufferPatterns.some(bp => bp.name === matched!.name);
        if (!formatOnly) payloadMatch = true;
        evidence.push({
          file,
          detail: formatOnly
            ? `Compiled executable (${matched.name}) — its code can't be reviewed or analysed`
            : `Binary pattern matched: ${matched.name}`,
        });
      }
    }

    // An executable header alone says "opaque native code", not "malicious":
    // a warning. Shellcode padding or a packed-eval wrapper stays critical.
    return h.fromEvidence(evidence, {
      passed: 'No suspicious binary patterns found in skill files',
      failed: (n) => `Found ${n} file(s) with suspicious binary patterns`,
      severity: payloadMatch ? 'critical' : 'warning',
    });
  },
});
