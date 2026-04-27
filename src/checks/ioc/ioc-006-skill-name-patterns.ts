import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { getIOCDatabase } from '../../ioc/database.js';

export const ioc006 = defineCheck({
  id: 'IOC-006',
  name: 'Skill Name Patterns',
  category: 'ioc',
  severity: 'warning',
  description: 'Match skill names against known malicious naming patterns',

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    const db = getIOCDatabase();
    const skillsDir = ctx.installation.skillsDir;

    if (!skillsDir) return h.passed('No skills directory found');

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

    return h.fromEvidence(evidence, {
      passed: 'No malicious skill name patterns detected',
      failed: (n) => `Found ${n} skill(s) with suspicious names`,
    });
  },
});
