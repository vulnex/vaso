import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { markUnreachable, queryPermissions, writableByOthers } from '../../core/permissions.js';
import { hermesManagedDir, managedFilePaths } from '../../adapters/hermes-managed.js';

/**
 * Hermes' administrator-managed scope (/etc/hermes or $HERMES_MANAGED_DIR)
 * overrides every user's config.yaml and .env, and its only protection is
 * filesystem permissions (hermes_cli/managed_scope.py: "v1 enforcement is
 * filesystem permissions only").
 */
export const hm011 = defineCheck({
  id: 'HM-011',
  name: 'Hermes Administrator-Managed Config Writable by Others',
  category: 'hermes',
  severity: 'critical',
  description: 'The administrator-managed Hermes scope (/etc/hermes, or $HERMES_MANAGED_DIR) or its config.yaml / .env is group- or world-writable — any such user can pin settings every Hermes process on the host applies over its own (approvals off, YOLO mode, an inference endpoint of their choosing, API keys).',
  supportedAgents: ['hermes'],
  supportedPlatforms: ['darwin', 'linux'],

  async run(ctx, h) {
    const dir = await hermesManagedDir(ctx.fs);
    if (!dir) return h.passed('No administrator-managed Hermes scope (/etc/hermes or $HERMES_MANAGED_DIR)');

    const evidence: Evidence[] = [];
    for (const path of [dir, ...managedFilePaths(dir)]) {
      try {
        const perms = await queryPermissions(ctx.fs, path);
        if (perms !== 'unsupported' && writableByOthers(perms)) {
          evidence.push({
            file: path,
            snippet: `mode 0${perms.octal}`,
            detail: path === dir
              ? 'Managed-scope directory is group/world writable — another user can drop in a config.yaml or .env every Hermes process applies'
              : 'Managed-scope file is group/world writable — another user can change settings every Hermes process applies over its own',
          });
        }
      } catch {
        // Absent — nothing to override with
      }
    }
    await markUnreachable(ctx.fs, evidence);
    return h.fromEvidence(evidence, {
      passed: `Administrator-managed Hermes scope ${dir} is writable only by its owner`,
      failed: (n) => `${n} administrator-managed Hermes path(s) writable by other users — they can override every Hermes user's settings`,
      fixDescription: `Make ${dir} and its files owned by root and not group/world writable (chmod 755 the directory, 644 config.yaml, 640 .env with a Hermes users group)`,
    });
  },
});
