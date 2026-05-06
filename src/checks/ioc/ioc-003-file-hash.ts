import { createHash } from 'node:crypto';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { getIOCDatabase } from '../../ioc/database.js';
import { getSkillFiles } from '../../core/utils.js';

export const ioc003 = defineCheck({
  id: 'IOC-003',
  name: 'File Hash Match',
  category: 'ioc',
  severity: 'critical',
  description: 'SHA-256 hash skill files and compare against known malicious hashes',

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    const db = getIOCDatabase();
    const hashSet = new Set(db.fileHashes);
    const skillsDir = ctx.installation.skillsDir;

    if (!skillsDir) return h.passed('No skills directory found');

    const files = ctx.skillFiles ?? await getSkillFiles(skillsDir, ctx.fs);

    for (const file of files) {
      try {
        const content = await ctx.fs.readFile(file);
        const hash = createHash('sha256').update(content).digest('hex');

        if (hashSet.has(hash)) {
          evidence.push({
            file,
            detail: `SHA-256 hash matches known malicious file: ${hash}`,
          });
        }
      } catch {}
    }

    return h.fromEvidence(evidence, {
      passed: 'No known malicious file hashes found',
      failed: (n) => `Found ${n} file(s) matching known malicious hashes`,
    });
  },
});
