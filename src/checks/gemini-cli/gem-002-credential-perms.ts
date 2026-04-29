import { join } from 'node:path';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

const CREDENTIAL_FILES = [
  'settings.json',
  'oauth_creds.json',
  'google_accounts.json',
  'mcp-oauth-tokens.json',
  'a2a-oauth-tokens.json',
];

export const gem002 = defineCheck({
  id: 'GEM-002',
  name: 'Gemini Credential File Permissions',
  category: 'coding-agent',
  severity: 'critical',
  description: 'Verify Gemini credential and OAuth token files are not group/world readable',
  supportedAgents: ['gemini-cli'],
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
      passed: 'Gemini credential files have restricted permissions',
      failed: (n) => `Found ${n} Gemini credential file(s) with overly permissive mode`,
      fixDescription: 'Run `chmod 600 ~/.gemini/{settings,oauth_creds,google_accounts,mcp-oauth-tokens}.json` to restrict access',
    });
  },
});
