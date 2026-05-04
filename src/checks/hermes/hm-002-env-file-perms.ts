import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

const SECRET_KEY_PATTERN = /(_API_KEY|_TOKEN|_SECRET|_KEY|BEARER|PASSWORD)\s*=/i;

export const hm002 = defineCheck({
  id: 'HM-002',
  name: 'Hermes .env Over-Permissive Permissions',
  category: 'hermes',
  severity: 'critical',
  description: 'Detect ~/.hermes/.env containing provider API keys / channel bot tokens with mode wider than 0600 — credentials readable by other local users.',
  supportedAgents: ['hermes'],
  supportedPlatforms: ['darwin', 'linux'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    for (const config of ctx.configs) {
      if (config.format !== 'env') continue;
      if (!SECRET_KEY_PATTERN.test(config.raw)) continue;
      try {
        const stat = await ctx.fs.stat(config.filePath);
        const perms = stat.mode & 0o777;
        if ((perms & 0o077) !== 0) {
          evidence.push({
            file: config.filePath,
            snippet: `mode 0${perms.toString(8)}`,
            detail: '.env contains provider/channel secrets and is readable by group or other users',
          });
        }
      } catch {
        // Can't stat — skip
      }
    }
    return h.fromEvidence(evidence, {
      passed: 'Secret-bearing Hermes .env files have restricted permissions',
      failed: () => 'Hermes .env contains secrets and is over-permissive — restrict to 0600',
      fixDescription: 'Run `chmod 600 ~/.hermes/.env`',
    });
  },
});
