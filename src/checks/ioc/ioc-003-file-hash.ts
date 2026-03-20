import { createHash } from 'node:crypto';
import type { CheckModule, ScanContext, CheckResult, Evidence } from '../../core/types.js';
import { getIOCDatabase } from '../../ioc/database.js';
import { getSkillFiles } from '../../core/utils.js';

export const ioc003: CheckModule = {
  id: 'IOC-003',
  name: 'File Hash Match',
  category: 'ioc',
  severity: 'critical',
  description: 'SHA-256 hash skill files and compare against known malicious hashes',

  async run(ctx: ScanContext): Promise<CheckResult> {
    const evidence: Evidence[] = [];
    const db = getIOCDatabase();
    const hashSet = new Set(db.fileHashes);
    const skillsDir = ctx.installation.skillsDir;

    if (!skillsDir) {
      return { id: 'IOC-003', name: 'File Hash Match', category: 'ioc', severity: 'critical', passed: true, message: 'No skills directory found' };
    }

    const files = await getSkillFiles(skillsDir);

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

    return {
      id: 'IOC-003',
      name: 'File Hash Match',
      category: 'ioc',
      severity: 'critical',
      passed: evidence.length === 0,
      message: evidence.length === 0
        ? 'No known malicious file hashes found'
        : `Found ${evidence.length} file(s) matching known malicious hashes`,
      evidence: evidence.length > 0 ? evidence : undefined,
    };
  },
};
