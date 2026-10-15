import { join } from 'node:path';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { accessibleByOthers, markUnreachable, queryPermissions } from '../../core/permissions.js';
import { restrictFilesToOwner } from '../../remediation/config-writer.js';

// Upstream writes both with mode 0600, so a wider mode means the file was
// created or copied by hand (a common first step: `cp .env.example .env`).
const CREDENTIAL_FILES: Array<[string, string]> = [
  ['.env', 'provider API keys and channel bot tokens (TELEGRAM_BOT_TOKEN, DISCORD_BOT_TOKEN, GITHUB_TOKEN, COMPOSIO_API_KEY, …)'],
  [join('atomic-mail', 'session.json'), 'the Atomic Mail session JWT'],
];

export const at005 = defineCheck({
  id: 'AT-005',
  name: 'Atomic Agent Credential File Permissions',
  category: 'atomic-agent',
  severity: 'critical',
  description: 'Detect <stateDir>/.env or <stateDir>/atomic-mail/session.json with a mode wider than 0600 — provider keys, bot tokens and the mail session JWT readable by other local users.',
  supportedAgents: ['atomic-agent'],
  supportedPlatforms: ['darwin', 'linux'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    for (const [rel, holds] of CREDENTIAL_FILES) {
      const file = join(ctx.installation.installDir, rel);
      try {
        if (!(await ctx.fs.access(file))) continue;
        const perms = await queryPermissions(ctx.fs, file);
        if (perms === 'unsupported' || !accessibleByOthers(perms)) continue;
        evidence.push({
          file,
          snippet: `mode 0${perms.octal}`,
          detail: `Holds ${holds} and is accessible to group or other users`,
        });
      } catch {
        // Can't stat — skip
      }
    }
    await markUnreachable(ctx.fs, evidence);
    return h.fromEvidence(evidence, {
      passed: 'Atomic Agent credential files are owner-only',
      failed: (n) => `${n} Atomic Agent credential file(s) readable beyond the owner — restrict to 0600`,
      fixable: true,
      fixDescription: 'Remove group/other access from ~/.atomic-agent/.env and ~/.atomic-agent/atomic-mail/session.json',
    });
  },

  async fix(ctx) {
    return restrictFilesToOwner('AT-005', CREDENTIAL_FILES.map(([rel]) => join(ctx.installation.installDir, rel)));
  },
});
