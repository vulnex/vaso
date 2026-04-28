import { join } from 'node:path';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

export const ly013 = defineCheck({
  id: 'LY-013',
  name: 'Edit Ledger Over-Permissive',
  category: 'lyrie',
  severity: 'warning',
  description: 'Verify ~/.lyrie/edits.json mode is 0600 — wider perms enable a TOCTOU race where another local process swaps the unifiedDiff between operator approval and EditEngine apply.',
  supportedAgents: ['lyrie'],
  supportedPlatforms: ['darwin', 'linux'],

  async run(ctx, h) {
    const path = join(ctx.installation.installDir, 'edits.json');
    if (!(await ctx.fs.access(path))) return h.passed('edits.json not present');

    const evidence: Evidence[] = [];
    try {
      const stat = await ctx.fs.stat(path);
      const perms = stat.mode & 0o777;
      if ((perms & 0o077) !== 0) {
        evidence.push({
          file: path,
          snippet: `mode 0${perms.toString(8)}`,
          detail: 'edits.json writable by group/other — TOCTOU race vector for diff swapping',
        });
      }
    } catch {
      // skip
    }

    return h.fromEvidence(evidence, {
      passed: 'edits.json has restrictive permissions',
      failed: () => 'edits.json is over-permissive',
      fixDescription: 'Run `chmod 600 ~/.lyrie/edits.json`',
    });
  },
});
