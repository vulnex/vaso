import type { CheckModule, ScanContext, CheckResult, Evidence } from '../../core/types.js';
import { getIOCDatabase } from '../../ioc/database.js';
import { detectTyposquatting } from '../../ioc/typosquat.js';

export const ioc005: CheckModule = {
  id: 'IOC-005',
  name: 'Typosquatting',
  category: 'ioc',
  severity: 'warning',
  description: 'Detect skills with names similar to trusted ones (Levenshtein distance <= 2)',

  async run(ctx: ScanContext): Promise<CheckResult> {
    const evidence: Evidence[] = [];
    const db = getIOCDatabase();
    const skillsDir = ctx.installation.skillsDir;

    if (!skillsDir) {
      return { id: 'IOC-005', name: 'Typosquatting', category: 'ioc', severity: 'warning', passed: true, message: 'No skills directory found' };
    }

    try {
      const entries = await ctx.fs.readdirEntries(skillsDir);
      for (const entry of entries) {
        if (!entry.isDirectory) continue;

        const match = detectTyposquatting(entry.name, db.trustedSkillNames);
        if (match) {
          evidence.push({
            file: skillsDir,
            detail: `Skill "${match.skillName}" is similar to trusted "${match.trustedName}" (distance: ${match.distance})`,
          });
        }
      }
    } catch {}

    return {
      id: 'IOC-005',
      name: 'Typosquatting',
      category: 'ioc',
      severity: 'warning',
      passed: evidence.length === 0,
      message: evidence.length === 0
        ? 'No typosquatting detected'
        : `Found ${evidence.length} potential typosquat(s)`,
      evidence: evidence.length > 0 ? evidence : undefined,
    };
  },
};
