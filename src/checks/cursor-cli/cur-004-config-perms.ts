import { join } from 'node:path';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { queryPermissions, accessibleByOthers } from '../../core/permissions.js';

const PROTECTED_FILES = ['cli-config.json', 'mcp.json'];

export const cur004 = defineCheck({
  id: 'CUR-004',
  name: 'Cursor Config File Permissions',
  category: 'coding-agent',
  severity: 'critical',
  description: 'Verify ~/.cursor/cli-config.json (and mcp.json) are not readable by group or other users',
  supportedAgents: ['cursor-cli'],
  supportedPlatforms: ['darwin', 'linux'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    for (const filename of PROTECTED_FILES) {
      const filePath = join(ctx.installation.installDir, filename);
      if (!(await ctx.fs.access(filePath))) continue;
      try {
        const perms = await queryPermissions(ctx.fs, filePath);
        // 'unsupported' (no evaluable permission model) → nothing to flag
        if (perms !== 'unsupported' && accessibleByOthers(perms)) {
          // Authoring detail: cli-config.json holds authInfo (email/userId/authId);
          // mcp.json may hold bearer tokens in headers. Either is a leak vector.
          evidence.push({
            file: filePath,
            snippet: `mode 0${perms.octal}`,
            detail: `${filename} is readable or writable by group/other — auth state and tokens may leak`,
          });
        }
      } catch {}
    }

    return h.fromEvidence(evidence, {
      passed: 'Cursor config files have restricted permissions',
      failed: (n) => `Found ${n} Cursor config file(s) with overly permissive mode`,
      fixDescription: 'Run `chmod 600 ~/.cursor/cli-config.json ~/.cursor/mcp.json` to restrict access to the owner',
    });
  },
});
