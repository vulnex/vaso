import { join } from 'node:path';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { markUnreachable, queryPermissions } from '../../core/permissions.js';
import { lyrieStateDir } from '../../adapters/lyrie.js';

export const ly015 = defineCheck({
  id: 'LY-015',
  name: 'Skills Directory World-Writable',
  category: 'lyrie',
  severity: 'warning',
  description: 'Verify ~/.lyrie/skills is not world-writable — Lyrie loads every SKILL.md under it into the agent, so a world-writable directory lets any local user plant instructions the agent follows. (Group write alone is not reported: Lyrie creates the directory with the default umask, and on user-private-group systems the group is the owner.)',
  supportedAgents: ['lyrie'],
  supportedPlatforms: ['darwin', 'linux'],

  async run(ctx, h) {
    const skillsDir = ctx.installation.skillsDir ?? join(lyrieStateDir(ctx.fs), 'skills');
    if (!(await ctx.fs.access(skillsDir))) return h.passed('Skills directory not present');

    const evidence: Evidence[] = [];
    try {
      const perms = await queryPermissions(ctx.fs, skillsDir);
      if (perms !== 'unsupported' && perms.worldWrite) {
        evidence.push({
          file: skillsDir,
          snippet: perms.description,
          detail: 'Skills directory is writable by any local user — skills can be planted',
        });
      }
    } catch {
      // skip
    }

    await markUnreachable(ctx.fs, evidence);
    return h.fromEvidence(evidence, {
      passed: 'Skills directory is not world-writable',
      failed: () => 'Skills directory is world-writable',
      fixDescription: 'Run `chmod 700 ~/.lyrie/skills`',
    });
  },
});
