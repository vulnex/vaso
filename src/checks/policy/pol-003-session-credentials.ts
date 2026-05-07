import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

export const pol003 = defineCheck({
  id: 'POL-003',
  name: 'Session Credential Permissions',
  category: 'policy',
  severity: 'warning',
  description: 'Check that adapter-declared session/token/auth files have restrictive permissions (0600)',
  supportedPlatforms: ['darwin', 'linux'],

  async run(ctx, h) {
    const paths = ctx.credentialPaths ?? [];
    if (paths.length === 0) {
      return h.passed('Adapter does not declare credential paths; skipping');
    }

    const evidence: Evidence[] = [];
    for (const fullPath of paths) {
      try {
        const stats = await ctx.fs.stat(fullPath);
        if (!stats.isFile()) continue;
        const mode = stats.mode & 0o777;
        if (mode & 0o077) {
          evidence.push({
            file: fullPath,
            detail: `Permissions: ${mode.toString(8)} (should be 600 or tighter)`,
          });
        }
      } catch {
        // File may not exist
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'All session/credential files have restrictive permissions',
      failed: (n) => `${n} session/credential file(s) have overly permissive permissions`,
    });
  },
});
