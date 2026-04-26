import type { CheckModule, ScanContext, CheckResult, Evidence } from '../../core/types.js';

export const cc007: CheckModule = {
  id: 'CC-007',
  name: 'apiKeyHelper Script Permissions',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Verify that an apiKeyHelper script is not world-writable',
  supportedAgents: ['claude-code'],

  async run(ctx: ScanContext): Promise<CheckResult> {
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
        // World-writable bit (others: write)
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

    return {
      id: 'CC-007',
      name: 'apiKeyHelper Script Permissions',
      category: 'coding-agent',
      severity: 'warning',
      passed: evidence.length === 0,
      message: evidence.length === 0
        ? 'apiKeyHelper script (if configured) has safe permissions'
        : `Found ${evidence.length} apiKeyHelper issue(s)`,
      evidence: evidence.length > 0 ? evidence : undefined,
      fixable: false,
      fixDescription: 'Run `chmod 700` on the apiKeyHelper script and ensure its parent directory is not world-writable',
    };
  },
};
