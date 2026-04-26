import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

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
      const path = helper.split(/\s+/)[0];

      try {
        if (!(await ctx.fs.access(path))) {
          evidence.push({
            file: config.filePath,
            snippet: `apiKeyHelper = ${helper}`,
            detail: 'apiKeyHelper script does not exist on disk',
          });
          continue;
        }
        const stat = await ctx.fs.stat(path);
        if ((stat.mode & 0o002) !== 0) {
          evidence.push({
            file: config.filePath,
            snippet: `${path} (mode ${(stat.mode & 0o777).toString(8)})`,
            detail: 'apiKeyHelper is world-writable — any local user can replace it and exfiltrate the key',
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
