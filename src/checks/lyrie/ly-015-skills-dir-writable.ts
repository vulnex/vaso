import { join } from 'node:path';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

export const ly015 = defineCheck({
  id: 'LY-015',
  name: 'Skills Directory Writable by Other Users',
  category: 'lyrie',
  severity: 'warning',
  description: 'Verify ~/.lyrie/skills/ is not group/world-writable — a writable skills directory lets any local user drop a malicious skill that runs in the agent context.',
  supportedAgents: ['lyrie'],
  supportedPlatforms: ['darwin', 'linux'],

  async run(ctx, h) {
    const skillsDir = ctx.installation.skillsDir ?? join(ctx.installation.installDir, 'skills');
    if (!(await ctx.fs.access(skillsDir))) return h.passed('Skills directory not present');

    const evidence: Evidence[] = [];
    try {
      const stats = await ctx.fs.stat(skillsDir);
      const mode = stats.mode & 0o777;
      if (mode & 0o022) {
        evidence.push({
          file: skillsDir,
          detail: `Permissions ${mode.toString(8)} — directory writable by group or world; arbitrary skills can be planted`,
        });
      }
    } catch {
      // skip
    }

    return h.fromEvidence(evidence, {
      passed: 'Skills directory has restrictive permissions',
      failed: () => 'Skills directory writable by other users',
      fixDescription: 'Run `chmod 700 ~/.lyrie/skills`',
    });
  },
});
