import { join } from 'node:path';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

export const ly004 = defineCheck({
  id: 'LY-004',
  name: 'DM Pairing Store Over-Permissive',
  category: 'lyrie',
  severity: 'warning',
  description: 'Verify ~/.lyrie/pairing.json mode is 0600 — Lyrie writes it that way at creation, but operators may chmod it later. Wider perms let other local users see who\'s paired and add fake "approved" entries.',
  supportedAgents: ['lyrie'],
  supportedPlatforms: ['darwin', 'linux'],

  async run(ctx, h) {
    const path = join(ctx.installation.installDir, 'pairing.json');
    if (!(await ctx.fs.access(path))) return h.passed('pairing.json not present');

    const evidence: Evidence[] = [];
    try {
      const stat = await ctx.fs.stat(path);
      const perms = stat.mode & 0o777;
      if ((perms & 0o077) !== 0) {
        evidence.push({
          file: path,
          snippet: `mode 0${perms.toString(8)}`,
          detail: 'pairing.json is over-permissive — other local users can read or modify the DM allowlist',
        });
      }
    } catch {
      // Can't stat — skip
    }

    return h.fromEvidence(evidence, {
      passed: 'pairing.json has restrictive permissions',
      failed: () => 'pairing.json is over-permissive',
      fixDescription: 'Run `chmod 600 ~/.lyrie/pairing.json`',
    });
  },
});
