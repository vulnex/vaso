import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { accessibleByOthers, markUnreachable, queryPermissions } from '../../core/permissions.js';

const SECRET_KEY_PATTERN = /(_API_KEY|_TOKEN|_SECRET|_KEY|BEARER|PASSWORD)\s*=/i;

export const hm002 = defineCheck({
  id: 'HM-002',
  name: 'Hermes .env Over-Permissive Permissions',
  category: 'hermes',
  severity: 'critical',
  description: 'Detect ~/.hermes/.env containing provider API keys / channel bot tokens with mode wider than 0600 — credentials readable by other local users. The administrator-managed .env (/etc/hermes or $HERMES_MANAGED_DIR) is flagged when world-readable.',
  supportedAgents: ['hermes'],
  supportedPlatforms: ['darwin', 'linux'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    for (const config of ctx.configs) {
      if (config.format !== 'env') continue;
      if (!SECRET_KEY_PATTERN.test(config.raw)) continue;
      try {
        const perms = await queryPermissions(ctx.fs, config.filePath);
        if (perms === 'unsupported') continue;
        if (config.managed) {
          // Every account that runs Hermes must read the administrator-managed
          // .env, so group access is by design; any local user is not
          if (perms.worldRead) {
            evidence.push({
              file: config.filePath,
              snippet: `mode 0${perms.octal}`,
              detail: 'Administrator-managed .env contains provider/channel secrets and is world-readable — every local account can read them (restrict it to a group of Hermes users, e.g. 0640)',
            });
          }
        } else if (accessibleByOthers(perms)) {
          evidence.push({
            file: config.filePath,
            snippet: `mode 0${perms.octal}`,
            detail: '.env contains provider/channel secrets and is readable by group or other users',
          });
        }
      } catch {
        // Can't stat — skip
      }
    }
    await markUnreachable(ctx.fs, evidence);
    return h.fromEvidence(evidence, {
      passed: 'Secret-bearing Hermes .env files have restricted permissions',
      failed: () => 'Hermes .env contains secrets and is over-permissive — restrict to 0600',
      fixDescription: 'Run `chmod 600 ~/.hermes/.env`',
    });
  },
});
