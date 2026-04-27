import { join } from 'node:path';
import { defineCheck } from '../../core/check-builder.js';
import { chmodFile } from '../../remediation/config-writer.js';

export const zc013 = defineCheck({
  id: 'ZC-013',
  name: '.secret_key Permissions',
  category: 'zeroclaw',
  severity: 'critical',
  description: 'Check if .secret_key file has overly permissive file permissions',
  supportedAgents: ['zeroclaw'],
  supportedPlatforms: ['linux', 'darwin'],

  async run(ctx, h) {
    const evidence = [];
    const keyPath = join(ctx.installation.installDir, '.secret_key');
    try {
      const stats = await ctx.fs.stat(keyPath);
      const mode = stats.mode & 0o777;
      if (mode !== 0o600) {
        evidence.push({
          file: keyPath,
          detail: `File permissions are ${mode.toString(8)} — should be 600`,
        });
      }
    } catch {}

    return h.fromEvidence(evidence, {
      passed: '.secret_key has appropriate permissions',
      failed: () => '.secret_key has overly permissive file permissions',
      fixable: true,
      fixDescription: 'Run: chmod 600 ~/.zeroclaw/.secret_key',
    });
  },

  async fix(ctx) {
    const keyPath = join(ctx.installation.installDir, '.secret_key');
    try {
      await chmodFile(keyPath, 0o600);
      return { checkId: 'ZC-013', applied: true, message: 'Set .secret_key permissions to 600' };
    } catch {
      return { checkId: 'ZC-013', applied: false, message: 'Failed to set permissions on .secret_key' };
    }
  },
});
