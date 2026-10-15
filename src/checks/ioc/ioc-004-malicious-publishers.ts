import { join } from 'node:path';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { listSkills } from '../../core/skill-walk.js';
import { getAllSkillsDirs } from '../../core/utils.js';
import { getIOCDatabase } from '../../ioc/database.js';

export const ioc004 = defineCheck({
  id: 'IOC-004',
  name: 'Malicious Publishers',
  category: 'ioc',
  severity: 'critical',
  description: 'Check skill metadata for known malicious publishers',

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    const db = getIOCDatabase();
    const publisherSet = new Set(db.maliciousPublishers.map(p => p.toLowerCase()));
    const skillsDirs = getAllSkillsDirs(ctx.installation);
    if (skillsDirs.length === 0) return h.passed('No skills directory found');

    const skills = await listSkills(ctx.fs, skillsDirs, { rootIsSkill: ctx.installation.agent === 'skill-audit' });
    for (const skill of skills) {
      for (const metaFile of ['package.json', 'skill.json', 'metadata.json']) {
        const metaPath = join(skill.dir, metaFile);
        try {
          const data = JSON.parse(await ctx.fs.readFile(metaPath));
          const author = String(data.author?.name ?? data.author ?? data.publisher ?? '').toLowerCase();

          if (publisherSet.has(author)) {
            evidence.push({
              file: metaPath,
              detail: `Skill "${skill.name}" by known malicious publisher: ${author}`,
            });
          }
        } catch {}
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'No known malicious publishers found',
      failed: (n) => `Found ${n} skill(s) from known malicious publishers`,
    });
  },
});
