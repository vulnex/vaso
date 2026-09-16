import { join } from 'node:path';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { queryPermissions, writableByOthers } from '../../core/permissions.js';

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
      const perms = await queryPermissions(ctx.fs, skillsDir);
      if (perms !== 'unsupported' && writableByOthers(perms)) {
        evidence.push({
          file: skillsDir,
          detail: `Permissions ${perms.octal} — directory writable by group or world; arbitrary skills can be planted`,
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
