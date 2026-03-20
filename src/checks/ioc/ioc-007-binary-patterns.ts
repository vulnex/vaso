import type { CheckModule, ScanContext, CheckResult, Evidence } from '../../core/types.js';
import { getIOCDatabase } from '../../ioc/database.js';
import { getSkillFiles } from '../../core/utils.js';

export const ioc007: CheckModule = {
  id: 'IOC-007',
  name: 'Binary Pattern Match',
  category: 'ioc',
  severity: 'critical',
  description: 'YARA-like byte/regex patterns on skill files (ELF/MachO/PE headers, shellcode, packed JS)',

  async run(ctx: ScanContext): Promise<CheckResult> {
    const evidence: Evidence[] = [];
    const skillsDir = ctx.installation.skillsDir;
    if (!skillsDir) {
      return { id: 'IOC-007', name: 'Binary Pattern Match', category: 'ioc', severity: 'critical', passed: true, message: 'No skills directory found' };
    }

    const db = getIOCDatabase();
    const files = ctx.skillFiles ?? await getSkillFiles(skillsDir);

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
            break; // One finding per file
          }
        }
      } catch {
        // Skip unreadable files
      }
    }

    return {
      id: 'IOC-007',
      name: 'Binary Pattern Match',
      category: 'ioc',
      severity: 'critical',
      passed: evidence.length === 0,
      message: evidence.length === 0
        ? 'No suspicious binary patterns found in skill files'
        : `Found ${evidence.length} file(s) with suspicious binary patterns`,
      evidence: evidence.length > 0 ? evidence : undefined,
    };
  },
};
