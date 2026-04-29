import { join } from 'node:path';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

const CREDENTIAL_FILES = [
  'settings.json',
  'oauth_creds.json',
  'mcp-oauth-tokens.json',
  'google_accounts.json',
  '.env',
];

export const qc002 = defineCheck({
  id: 'QC-002',
  name: 'Qwen Credential File Permissions',
  category: 'coding-agent',
  severity: 'critical',
  description: 'Verify Qwen credential and OAuth token files are not group/world readable',
  supportedAgents: ['qwen-code'],
  supportedPlatforms: ['darwin', 'linux'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    for (const filename of CREDENTIAL_FILES) {
      const filePath = join(ctx.installation.installDir, filename);
      if (!(await ctx.fs.access(filePath))) continue;
      try {
        const stat = await ctx.fs.stat(filePath);
        const perms = stat.mode & 0o777;
        if ((perms & 0o077) !== 0) {
          evidence.push({
            file: filePath,
            snippet: `mode 0${perms.toString(8)}`,
            detail: `${filename} is readable or writable by group/other — credentials may leak`,
          });
        }
      } catch {}
    }

    return h.fromEvidence(evidence, {
      passed: 'Qwen credential files have restricted permissions',
      failed: (n) => `Found ${n} Qwen credential file(s) with overly permissive mode`,
      fixDescription: 'Run `chmod 600 ~/.qwen/{settings,oauth_creds,mcp-oauth-tokens,google_accounts}.json ~/.qwen/.env` to restrict access',
    });
  },
});
