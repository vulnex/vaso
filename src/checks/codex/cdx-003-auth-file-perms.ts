import { join } from 'node:path';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

export const cdx003 = defineCheck({
  id: 'CDX-003',
  name: 'Codex Auth File Permissions',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Verify that ~/.codex/auth.json is not readable by other users',
  supportedAgents: ['codex'],
  supportedPlatforms: ['darwin', 'linux'],

  async run(ctx, h) {
    const authPath = join(ctx.installation.installDir, 'auth.json');
    if (!(await ctx.fs.access(authPath))) return h.passed('auth.json not present');

    const evidence: Evidence[] = [];
    try {
      const stat = await ctx.fs.stat(authPath);
      const perms = stat.mode & 0o777;
      if ((perms & 0o077) !== 0) {
        evidence.push({
          file: authPath,
          snippet: `mode 0${perms.toString(8)}`,
          detail: 'auth.json is readable or writable by group/other — credentials may be exposed',
        });
      }
    } catch {
      // Can't stat — skip silently
    }

    return h.fromEvidence(evidence, {
      passed: 'Codex auth.json has restricted permissions',
      failed: () => 'Codex auth.json is over-permissive — restrict it to 0600',
      fixDescription: 'Run `chmod 600 ~/.codex/auth.json` to restrict access to the owner',
    });
  },
});
