import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { accessibleByOthers, markUnreachable, queryPermissions } from '../../core/permissions.js';
import { restrictFilesToOwner } from '../../remediation/config-writer.js';

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
        const perms = await queryPermissions(ctx.fs, fullPath);
        if (perms !== 'unsupported' && accessibleByOthers(perms)) {
          evidence.push({
            file: fullPath,
            detail: `Permissions: ${perms.octal} (should be 600 or tighter)`,
          });
        }
      } catch {
        // File may not exist
      }
    }

    await markUnreachable(ctx.fs, evidence);
    return h.fromEvidence(evidence, {
      passed: 'All session/credential files have restrictive permissions',
      failed: (n) => `${n} session/credential file(s) have overly permissive permissions`,
      fixable: true,
      fixDescription: 'Remove group/other access (chmod go-rwx)',
    });
  },

  // Credential files that aren't loaded configs (credentials.json, auth.json,
  // token stores) are only reported here; CFG-003's fix never reached them.
  async fix(ctx) {
    return restrictFilesToOwner('POL-003', ctx.credentialPaths ?? []);
  },
});
