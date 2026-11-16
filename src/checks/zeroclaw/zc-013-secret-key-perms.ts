import { join } from 'node:path';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { accessibleByOthers, markUnreachable, queryPermissions } from '../../core/permissions.js';
import { restrictFilesToOwner } from '../../remediation/config-writer.js';
import { permissionFixTargets } from '../../remediation/fix-refusal.js';

export const zc013 = defineCheck({
  id: 'ZC-013',
  name: '.secret_key Permissions',
  category: 'zeroclaw',
  severity: 'critical',
  description:
    'Check that the ChaCha20 master key (<config dir>/.secret_key) is owner-only — anyone who can read it decrypts every enc2: secret in config.toml and auth-profiles.json',
  supportedAgents: ['zeroclaw'],
  supportedPlatforms: ['linux', 'darwin'],

  fixTargets: permissionFixTargets,

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    const keyPath = join(ctx.installation.installDir, '.secret_key');
    try {
      const perms = await queryPermissions(ctx.fs, keyPath);
      if (perms !== 'unsupported' && accessibleByOthers(perms)) {
        evidence.push({
          file: keyPath,
          detail: `File permissions are ${perms.octal} — should be 600`,
        });
      }
    } catch {
      // No key yet: created on first secret encryption.
    }

    await markUnreachable(ctx.fs, evidence);
    return h.fromEvidence(evidence, {
      passed: '.secret_key is owner-only (or not created yet)',
      failed: () => '.secret_key is accessible to other users',
      fixable: true,
      fixDescription: 'Run: chmod go-rwx <config dir>/.secret_key',
    });
  },

  async fix(ctx) {
    const keyPath = join(ctx.installation.installDir, '.secret_key');
    return restrictFilesToOwner('ZC-013', [keyPath]);
  },
});
