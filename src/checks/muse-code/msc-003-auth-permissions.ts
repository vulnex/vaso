import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { accessibleByOthers, markUnreachable, queryPermissions } from '../../core/permissions.js';
import { restrictFilesToOwner } from '../../remediation/config-writer.js';
import { permissionFixTargets } from '../../remediation/fix-refusal.js';
import { museAuthPath } from '../../adapters/muse-code.js';
import { isProjectInstall } from './shared.js';

export const msc003 = defineCheck({
  id: 'MSC-003',
  name: 'Muse Code Credential File Permissions',
  category: 'coding-agent',
  severity: 'critical',
  description: 'Verify the Meta Muse Code credential file (~/.config/muse/auth.json or $MUSE_AUTH_PATH — provider API keys in plaintext, written 0600) is not accessible to other local users',
  supportedAgents: ['muse-code'],
  supportedPlatforms: ['darwin', 'linux'],

  fixTargets: permissionFixTargets,

  async run(ctx, h) {
    if (isProjectInstall(ctx)) return h.passed('Credentials are user-level — evaluated on the user installation');
    const path = museAuthPath(ctx.fs.homedir(), ctx.fs);
    const evidence: Evidence[] = [];
    try {
      if (await ctx.fs.access(path)) {
        const perms = await queryPermissions(ctx.fs, path);
        if (perms !== 'unsupported' && accessibleByOthers(perms)) {
          evidence.push({ file: path, snippet: `mode 0${perms.octal}`, detail: 'Holds Muse Code provider API keys in plaintext and is accessible to group or other users' });
        }
      }
    } catch {
      // can't stat — skip
    }
    await markUnreachable(ctx.fs, evidence);
    return h.fromEvidence(evidence, {
      passed: 'Muse Code credential file is owner-only (or absent)',
      failed: () => 'Muse Code credential file is accessible beyond the owner',
      fixable: true,
      fixDescription: 'chmod 600 the Muse Code auth.json; run `muse logout` and log in again if exposure is suspected',
    });
  },

  async fix(ctx) {
    return restrictFilesToOwner('MSC-003', [museAuthPath(ctx.fs.homedir(), ctx.fs)]);
  },
});
