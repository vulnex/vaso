import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

const SECRET_KEY_PATTERN = /(_API_KEY|_TOKEN|_SECRET|_TOKEN_ID|_TOKEN_SECRET)\s*=/;

export const ly006 = defineCheck({
  id: 'LY-006',
  name: 'Plaintext Secrets in Over-Permissive .env',
  category: 'lyrie',
  severity: 'critical',
  description: 'Detect .env files containing API keys / channel tokens with mode wider than 0600 — credentials are readable by other local users.',
  supportedAgents: ['lyrie'],
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
            detail: '.env contains secrets and is readable/writable by group or other users',
          });
        }
      } catch {
        // Can't stat — skip
      }
    }
    return h.fromEvidence(evidence, {
      passed: 'Secret-bearing .env files have restricted permissions',
      failed: () => '.env contains secrets and is over-permissive — restrict to 0600',
      fixDescription: 'Run `chmod 600 ~/.lyrie/.env` to restrict access to the owner',
    });
  },
});
