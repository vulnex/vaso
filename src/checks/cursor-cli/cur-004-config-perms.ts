import { basename, join } from 'node:path';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { accessibleByOthers, markUnreachable, queryPermissions } from '../../core/permissions.js';
import { configHoldsSecret } from '../../core/secret-values.js';

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

    // plus a cli-config.json relocated by CURSOR_CONFIG_DIR / XDG_CONFIG_HOME
    const paths = new Set(PROTECTED_FILES.map(f => join(ctx.installation.installDir, f)));
    for (const c of ctx.configs) if (basename(c.filePath) === 'cli-config.json') paths.add(c.filePath);

    for (const filePath of paths) {
      const filename = basename(filePath);
      if (!(await ctx.fs.access(filePath))) continue;
      // Sensitive only with content to leak: cli-config.json's authInfo
      // (account email / user and auth IDs) or a secret in either file
      const config = ctx.configs.find(c => c.filePath === filePath);
      const data = config?.data as Record<string, unknown> | undefined;
      if (config && !(filename === 'cli-config.json' && data?.authInfo) && !configHoldsSecret(data)) continue;
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

    await markUnreachable(ctx.fs, evidence);
    return h.fromEvidence(evidence, {
      passed: 'Cursor config files have restricted permissions',
      failed: (n) => `Found ${n} Cursor config file(s) with overly permissive mode`,
      fixDescription: 'Run `chmod 600 ~/.cursor/cli-config.json ~/.cursor/mcp.json` to restrict access to the owner',
    });
  },
});
