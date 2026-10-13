import { join } from 'node:path';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { queryPermissions } from '../../core/permissions.js';

export const cc007 = defineCheck({
  id: 'CC-007',
  name: 'apiKeyHelper Script Permissions',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Verify that an apiKeyHelper script is not world-writable',
  supportedAgents: ['claude-code'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      const helper = config.data.apiKeyHelper;
      if (typeof helper !== 'string' || helper.length === 0) continue;

      // Strip any inline arguments — we only care about the executable path
      const first = helper.split(/\s+/)[0];
      const path = first === '~' || first.startsWith('~/') ? join(ctx.fs.homedir(), first.slice(1)) : first;

      try {
        if (!(await ctx.fs.access(path))) {
          // A snapshot holds only what the probe collected — the script's
          // path comes from settings, so absence there says nothing.
          if (ctx.fs.kind === 'snapshot') continue;
          evidence.push({
            file: config.filePath,
            snippet: `apiKeyHelper = ${helper}`,
            detail: 'apiKeyHelper script does not exist on disk',
          });
          continue;
        }
        const perms = await queryPermissions(ctx.fs, path);
        if (perms !== 'unsupported' && perms.worldWrite) {
          // Evidence on the script itself — the settings file's own mode is
          // CFG-003/POL-003's finding, which a shared file would hide
          evidence.push({
            file: path,
            snippet: `apiKeyHelper = ${helper} (mode ${perms.octal})`,
            detail: `apiKeyHelper (set in ${config.filePath}) is world-writable — any local user can replace it and exfiltrate the key`,
          });
        }
      } catch {
        // stat failed — skip
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'apiKeyHelper script (if configured) has safe permissions',
      failed: (n) => `Found ${n} apiKeyHelper issue(s)`,
      fixDescription: 'Run `chmod 700` on the apiKeyHelper script and ensure its parent directory is not world-writable',
    });
  },
});
