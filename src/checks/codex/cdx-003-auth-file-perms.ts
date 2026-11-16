import { join } from 'node:path';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { accessibleByOthers, markUnreachable, queryPermissions } from '../../core/permissions.js';
import { restrictFilesToOwner } from '../../remediation/config-writer.js';
import { permissionFixTargets } from '../../remediation/fix-refusal.js';

export const cdx003 = defineCheck({
  id: 'CDX-003',
  name: 'Codex Auth File Permissions',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Verify that ~/.codex/auth.json is not readable by other users',
  supportedAgents: ['codex'],
  supportedPlatforms: ['darwin', 'linux'],

  fixTargets: permissionFixTargets,

  async run(ctx, h) {
    const authPath = join(ctx.installation.installDir, 'auth.json');
    if (!(await ctx.fs.access(authPath))) return h.passed('auth.json not present');

    const evidence: Evidence[] = [];
    try {
      const perms = await queryPermissions(ctx.fs, authPath);
      if (perms !== 'unsupported' && accessibleByOthers(perms)) {
        evidence.push({
          file: authPath,
          snippet: `mode 0${perms.octal}`,
          detail: 'auth.json is readable or writable by group/other — credentials may be exposed',
        });
      }
    } catch {
      // Can't stat — skip silently
    }

    await markUnreachable(ctx.fs, evidence);
    return h.fromEvidence(evidence, {
      passed: 'Codex auth.json has restricted permissions',
      failed: () => 'Codex auth.json is over-permissive — restrict it to 0600',
      fixable: true,
      fixDescription: 'Remove group/other access from auth.json (chmod go-rwx ~/.codex/auth.json)',
    });
  },

  async fix(ctx) {
    return restrictFilesToOwner('CDX-003', [join(ctx.installation.installDir, 'auth.json')]);
  },
});
