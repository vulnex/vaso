import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { getIOCDatabase } from '../../ioc/database.js';
import { skillFilesOf, skillsDirsOf } from '../skills/skill-files.js';
import { readCappedBytes } from '../../core/file-limits.js';

function bytesStartWith(haystack: Uint8Array, needle: Uint8Array): boolean {
  if (haystack.length < needle.length) return false;
  for (let i = 0; i < needle.length; i++) {
    if (haystack[i] !== needle[i]) return false;
  }
  return true;
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

      // Buffer patterns represent executable magic bytes and must match at
      // file offset 0. Reading the file as bytes lets us avoid the latin1
      // substring search, which used to match the 2-byte PE magic ("MZ")
      // anywhere in the file — including inside identifiers like "xMZx".
      if (bufferPatterns.length > 0) {
        try {
          const bytes = await readCappedBytes(ctx.fs, file);
          for (const bp of bufferPatterns) {
            if (bytesStartWith(bytes, bp.pattern as Uint8Array)) {
              matched = { name: bp.name };
              break;
            }
          }
        } catch {}
      }

      // Regex patterns operate on file text (e.g. packed-JS wrappers).
      if (!matched) {
        const regexPatterns = db.binaryPatterns.filter(bp => bp.type === 'regex');
        if (regexPatterns.length > 0) {
          try {
            const content = Buffer.from(await readCappedBytes(ctx.fs, file)).toString('utf-8');
            for (const bp of regexPatterns) {
              if ((bp.pattern as RegExp).test(content)) {
                matched = { name: bp.name };
                break;
              }
            }
          } catch {}
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
