import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { chmodFile } from '../../remediation/config-writer.js';

export const cfg003 = defineCheck({
  id: 'CFG-003',
  name: 'Credential Config Permissions',
  category: 'config',
  severity: 'warning',
  description: 'Check that credential-bearing config files have restrictive permissions (600 or tighter)',
  supportedPlatforms: ['darwin', 'linux'],

  async run(ctx, h) {
    const credentialPaths = new Set(ctx.credentialPaths ?? []);
    if (credentialPaths.size === 0) {
      return h.passed('Adapter does not declare credential paths; skipping');
    }

    const evidence: Evidence[] = [];
    for (const config of ctx.configs) {
      if (!credentialPaths.has(config.filePath)) continue;
      try {
        const stats = await ctx.fs.stat(config.filePath);
        const mode = stats.mode & 0o777;
        if (mode & 0o077) {
          evidence.push({
            file: config.filePath,
            detail: `Permissions: ${mode.toString(8)} (should be 600 or tighter)`,
          });
        }
      } catch {
        // File may not exist
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'All credential config files have restrictive permissions',
      failed: (n) => `${n} credential config file(s) have overly permissive permissions`,
      fixable: true,
      fixDescription: 'Set permissions to 600 (chmod 600)',
    });
  },

  async fix(ctx) {
    const credentialPaths = new Set(ctx.credentialPaths ?? []);
    let fixed = 0;
    for (const config of ctx.configs) {
      if (!credentialPaths.has(config.filePath)) continue;
      try {
        await chmodFile(config.filePath, 0o600);
        fixed++;
      } catch {
        // File may not exist
      }
    }
    return {
      checkId: 'CFG-003',
      applied: fixed > 0,
      message: fixed > 0 ? `Set permissions to 600 on ${fixed} file(s)` : 'No files to fix',
    };
  },
});
