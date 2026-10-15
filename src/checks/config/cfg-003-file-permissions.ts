import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { accessibleByOthers, markUnreachable, queryPermissions } from '../../core/permissions.js';
import { restrictFilesToOwner } from '../../remediation/config-writer.js';
import { configHoldsSecret } from '../../core/secret-values.js';
import { basename } from 'node:path';

/** Files that are credentials by what they are, whatever they hold right now. */
// PicoClaw's .security.yml is its secret store (the place api keys move to)
const CREDENTIAL_FILE_NAME = /(?:^\.env(?:\.|$)|^\.security\.ya?ml$|credential|auth|token|secret|keystore|\.key$|\.pem$)/i;

/**
 * A declared credential path that is ordinary settings (an agent's
 * settings.json, written with the default umask) exposes something only when
 * it holds a secret; a group-readable settings file with none is not a leak.
 */
function exposesCredentials(config: { filePath: string; data: unknown }): boolean {
  return CREDENTIAL_FILE_NAME.test(basename(config.filePath)) || configHoldsSecret(config.data);
}

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
      if (!exposesCredentials(config)) continue;
      try {
        const perms = await queryPermissions(ctx.fs, config.filePath);
        if (perms !== 'unsupported' && accessibleByOthers(perms)) {
          evidence.push({
            file: config.filePath,
            detail: `Permissions: ${perms.octal} (should be 600 or tighter)`,
          });
        }
      } catch {
        // File may not exist
      }
    }

    await markUnreachable(ctx.fs, evidence);
    return h.fromEvidence(evidence, {
      passed: 'All credential config files have restrictive permissions',
      failed: (n) => `${n} credential config file(s) have overly permissive permissions`,
      fixable: true,
      fixDescription: 'Remove group/other access (chmod go-rwx)',
    });
  },

  async fix(ctx) {
    const credentialPaths = new Set(ctx.credentialPaths ?? []);
    return restrictFilesToOwner('CFG-003', ctx.configs.filter(c => credentialPaths.has(c.filePath) && exposesCredentials(c)).map(c => c.filePath));
  },
});
