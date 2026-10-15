import { join } from 'node:path';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { accessibleByOthers, markUnreachable, queryPermissions } from '../../core/permissions.js';
import { qc001 } from './qc-001-plaintext-api-key.js';

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
      // settings.json is ordinary configuration (written with the default
      // umask); it is a credential file only when it holds a secret, by QC-001's rules
      if (filename === 'settings.json') {
        const settings = ctx.configs.find(c => c.filePath === filePath);
        if (!settings || (await qc001.run({ ...ctx, configs: [settings] })).passed) continue;
      }
      try {
        const perms = await queryPermissions(ctx.fs, filePath);
        // 'unsupported' (no evaluable permission model) → nothing to flag
        if (perms !== 'unsupported' && accessibleByOthers(perms)) {
          evidence.push({
            file: filePath,
            snippet: `mode 0${perms.octal}`,
            detail: `${filename} is readable or writable by group/other — credentials may leak`,
          });
        }
      } catch {}
    }

    await markUnreachable(ctx.fs, evidence);
    return h.fromEvidence(evidence, {
      passed: 'Qwen credential files have restricted permissions',
      failed: (n) => `Found ${n} Qwen credential file(s) with overly permissive mode`,
      fixDescription: 'Run `chmod 600 ~/.qwen/{settings,oauth_creds,mcp-oauth-tokens,google_accounts}.json ~/.qwen/.env` to restrict access',
    });
  },
});
