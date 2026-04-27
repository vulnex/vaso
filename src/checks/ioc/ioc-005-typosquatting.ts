import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { getIOCDatabase } from '../../ioc/database.js';
import { detectTyposquatting } from '../../ioc/typosquat.js';

export const ioc005 = defineCheck({
  id: 'IOC-005',
  name: 'Typosquatting',
  category: 'ioc',
  severity: 'warning',
  description: 'Detect skills with names similar to trusted ones (Levenshtein distance <= 2)',

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    const db = getIOCDatabase();
    const skillsDir = ctx.installation.skillsDir;

    if (!skillsDir) return h.passed('No skills directory found');

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

    return h.fromEvidence(evidence, {
      passed: 'No typosquatting detected',
      failed: (n) => `Found ${n} potential typosquat(s)`,
    });
  },
});
