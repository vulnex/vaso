import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { getIOCDatabase } from '../../ioc/database.js';
import { skillFilesOf, skillsDirsOf } from '../skills/skill-files.js';
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
const NEAR_RUN = 64;
const MAX_RUNS = 1000;

/**
 * Whether a run of 16+ NULs hides something. A run of zeros alone is not
 * shellcode — model weights, arrays and padded data are full of them. It is
 * suspicious inside a script (extension or shebang; Node runs one with NULs
 * in it, padded to get past readers), or in any other file next to
 * machine-code bytes. Known data formats never are.
 */
function nulPaddingSuspicious(file: string, bytes: Uint8Array, content: string): boolean {
  if (isScriptFile(file, content)) return true;
  if (DATA_EXTENSIONS.has(extname(file).toLowerCase())) return false;
  if (bytes.every(b => b === 0)) return false;
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
          if (SHELLCODE_BYTES.some(sig => sig.every((x, k) => bytes[j + k] === x))) return true;
        }
      }
    }
    i = end;
  }
  return false;
}

export const ioc007 = defineCheck({
  id: 'IOC-007',
  name: 'Binary Pattern Match',
  category: 'ioc',
  severity: 'critical',
  description: 'YARA-like byte/regex patterns on skill files (ELF/MachO/PE headers anchored at offset 0; shellcode / packed JS via regex)',

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    if (skillsDirsOf(ctx).length === 0) return h.passed('No skills directory found');

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
        const head = await ctx.fs.readHead?.(file, 64).catch(() => undefined);
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
            // NUL runs are what compiled code (a universal Mach-O) is made of
            if (format && bp.name === 'NUL-padding shellcode') continue;
            if ((bp.pattern as RegExp).test(content)) {
              if (bp.name === 'NUL-padding shellcode' && !nulPaddingSuspicious(file, bytes, content)) continue;
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
