import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { getIOCDatabase } from '../../ioc/database.js';
import { getSkillFiles } from '../../core/utils.js';

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
    const skillsDir = ctx.installation.skillsDir;
    if (!skillsDir) return h.passed('No skills directory found');

    const db = getIOCDatabase();
    const files = ctx.skillFiles ?? await getSkillFiles(skillsDir, ctx.fs);

    for (const file of files) {
      let matched: { name: string } | undefined;

      // Buffer patterns represent executable magic bytes and must match at
      // file offset 0. Reading the file as bytes lets us avoid the latin1
      // substring search, which used to match the 2-byte PE magic ("MZ")
      // anywhere in the file — including inside identifiers like "xMZx".
      const bufferPatterns = db.binaryPatterns.filter(bp => bp.type === 'buffer');
      if (bufferPatterns.length > 0) {
        try {
          const bytes = await ctx.fs.readBytes(file);
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
            const content = await ctx.fs.readFile(file);
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
        evidence.push({
          file,
          detail: `Binary pattern matched: ${matched.name}`,
        });
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'No suspicious binary patterns found in skill files',
      failed: (n) => `Found ${n} file(s) with suspicious binary patterns`,
    });
  },
});
