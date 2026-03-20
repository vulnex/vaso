import type { CheckModule, ScanContext, CheckResult, Evidence } from '../../core/types.js';
import { getIOCDatabase } from '../../ioc/database.js';

export const ioc006: CheckModule = {
  id: 'IOC-006',
  name: 'Skill Name Patterns',
  category: 'ioc',
  severity: 'warning',
  description: 'Match skill names against known malicious naming patterns',

  async run(ctx: ScanContext): Promise<CheckResult> {
    const evidence: Evidence[] = [];
    const db = getIOCDatabase();
    const skillsDir = ctx.installation.skillsDir;

    if (!skillsDir) {
      return { id: 'IOC-006', name: 'Skill Name Patterns', category: 'ioc', severity: 'warning', passed: true, message: 'No skills directory found' };
    }

    try {
      const entries = await ctx.fs.readdirEntries(skillsDir);
      for (const entry of entries) {
        if (!entry.isDirectory) continue;

        for (const pattern of db.maliciousSkillPatterns) {
          if (pattern.test(entry.name)) {
            evidence.push({
              file: skillsDir,
              detail: `Skill "${entry.name}" matches malicious name pattern: ${pattern.source}`,
            });
            break;
          }
        }
      }
    } catch {}

    return {
      id: 'IOC-006',
      name: 'Skill Name Patterns',
      category: 'ioc',
      severity: 'warning',
      passed: evidence.length === 0,
      message: evidence.length === 0
        ? 'No malicious skill name patterns detected'
        : `Found ${evidence.length} skill(s) with suspicious names`,
      evidence: evidence.length > 0 ? evidence : undefined,
    };
  },
};
