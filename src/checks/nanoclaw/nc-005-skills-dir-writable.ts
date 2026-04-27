import type { Evidence } from '../../core/types.js';
import { join } from 'node:path';
import { defineCheck } from '../../core/check-builder.js';

export const nc005 = defineCheck({
  id: 'NC-005',
  name: 'Skills Directory World-Writable',
  category: 'nanoclaw',
  severity: 'warning',
  description: 'Verify the NanoClaw skills directory is not group/world-writable. A writable skills directory lets any local user drop a malicious skill that runs in the agent context.',
  supportedAgents: ['nanoclaw'],
  supportedPlatforms: ['darwin', 'linux'],

  async run(ctx, h) {
    const skillsDir = ctx.installation.skillsDir ?? join(ctx.installation.installDir, 'skills');
    if (!(await ctx.fs.access(skillsDir))) {
      return h.passed('Skills directory not present');
    }

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
    });
  },
});
