import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { getIOCDatabase } from '../../ioc/database.js';
import { getSkillFiles } from '../../core/utils.js';

export const ioc007 = defineCheck({
  id: 'IOC-007',
  name: 'Binary Pattern Match',
  category: 'ioc',
  severity: 'critical',
  description: 'YARA-like byte/regex patterns on skill files (ELF/MachO/PE headers, shellcode, packed JS)',

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    const skillsDir = ctx.installation.skillsDir;
    if (!skillsDir) return h.passed('No skills directory found');

    const db = getIOCDatabase();
    const files = ctx.skillFiles ?? await getSkillFiles(skillsDir, ctx.fs);

    for (const file of files) {
      try {
        const content = await ctx.fs.readFile(file);

        for (const bp of db.binaryPatterns) {
          let matched = false;

          if (bp.type === 'buffer') {
            matched = content.includes((bp.pattern as Buffer).toString('latin1'));
          } else {
            matched = (bp.pattern as RegExp).test(content);
          }

          if (matched) {
            evidence.push({
              file,
              detail: `Binary pattern matched: ${bp.name}`,
            });
            break;
          }
        }
      } catch {}
    }

    return h.fromEvidence(evidence, {
      passed: 'No suspicious binary patterns found in skill files',
      failed: (n) => `Found ${n} file(s) with suspicious binary patterns`,
    });
  },
});
