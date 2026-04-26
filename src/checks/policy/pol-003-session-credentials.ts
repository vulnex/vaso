import { join } from 'node:path';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

const CREDENTIAL_FILE_PATTERNS = [
  /session/i,
  /token/i,
  /credential/i,
  /auth/i,
  /\.secret_key$/i,
];

export const pol003 = defineCheck({
  id: 'POL-003',
  name: 'Session Credential Permissions',
  category: 'policy',
  severity: 'warning',
  description: 'Check that session/token/auth files have restrictive permissions (0600)',
  supportedPlatforms: ['darwin', 'linux'],

  async run(ctx, h) {
    const installDir = ctx.installation.installDir;

    let entries: { name: string; isFile: boolean; isDirectory: boolean; parentPath?: string }[];
    try {
      entries = await ctx.fs.readdirEntries(installDir, { recursive: true });
    } catch {
      return h.passed('Install directory not accessible');
    }

    const evidence: Evidence[] = [];
    for (const entry of entries) {
      if (!entry.isFile) continue;

      const matches = CREDENTIAL_FILE_PATTERNS.some(p => p.test(entry.name));
      if (!matches) continue;

      const fullPath = entry.parentPath ? join(entry.parentPath, entry.name) : join(installDir, entry.name);
      try {
        const stats = await ctx.fs.stat(fullPath);
        const mode = stats.mode & 0o777;
        if (mode & 0o077) {
          evidence.push({
            file: fullPath,
            detail: `Permissions: ${mode.toString(8)} (should be 600 or tighter)`,
          });
        }
      } catch {
        // File may not be accessible
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'All session/credential files have restrictive permissions',
      failed: (n) => `${n} session/credential file(s) have overly permissive permissions`,
    });
  },
});
