import { join } from 'node:path';
import type { CheckModule, ScanContext, CheckResult, Evidence } from '../../core/types.js';
import { getIOCDatabase } from '../../ioc/database.js';

export const ioc004: CheckModule = {
  id: 'IOC-004',
  name: 'Malicious Publishers',
  category: 'ioc',
  severity: 'critical',
  description: 'Check skill metadata for known malicious publishers',

  async run(ctx: ScanContext): Promise<CheckResult> {
    const evidence: Evidence[] = [];
    const db = getIOCDatabase();
    const publisherSet = new Set(db.maliciousPublishers.map(p => p.toLowerCase()));
    const skillsDir = ctx.installation.skillsDir;

    if (!skillsDir) {
      return { id: 'IOC-004', name: 'Malicious Publishers', category: 'ioc', severity: 'critical', passed: true, message: 'No skills directory found' };
    }

    // Look for package.json, skill.json, or metadata files in skill dirs
    try {
      const entries = await ctx.fs.readdirEntries(skillsDir);
      for (const entry of entries) {
        if (!entry.isDirectory) continue;

        const metadataFiles = ['package.json', 'skill.json', 'metadata.json'];
        for (const metaFile of metadataFiles) {
          const metaPath = join(skillsDir, entry.name, metaFile);
          try {
            const content = await ctx.fs.readFile(metaPath);
            const data = JSON.parse(content);
            const author = (data.author?.name ?? data.author ?? data.publisher ?? '').toLowerCase();

            if (publisherSet.has(author)) {
              evidence.push({
                file: metaPath,
                detail: `Skill "${entry.name}" by known malicious publisher: ${author}`,
              });
            }
          } catch {}
        }
      }
    } catch {}

    return {
      id: 'IOC-004',
      name: 'Malicious Publishers',
      category: 'ioc',
      severity: 'critical',
      passed: evidence.length === 0,
      message: evidence.length === 0
        ? 'No known malicious publishers found'
        : `Found ${evidence.length} skill(s) from known malicious publishers`,
      evidence: evidence.length > 0 ? evidence : undefined,
    };
  },
};
