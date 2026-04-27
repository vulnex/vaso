import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { chmodFile } from '../../remediation/config-writer.js';

export const nc002 = defineCheck({
  id: 'NC-002',
  name: 'Mount Allowlist File Writable',
  category: 'nanoclaw',
  severity: 'critical',
  description: 'Verify mount-allowlist.json is not group/world-writable. A writable allowlist lets any local user grant the agent additional filesystem scope.',
  supportedAgents: ['nanoclaw'],
  supportedPlatforms: ['darwin', 'linux'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      if (!config.filePath.endsWith('mount-allowlist.json')) continue;
      try {
        const stats = await ctx.fs.stat(config.filePath);
        const mode = stats.mode & 0o777;
        if (mode & 0o022) {
          evidence.push({
            file: config.filePath,
            detail: `Permissions ${mode.toString(8)} — group or world writable (should be 600)`,
          });
        }
      } catch {
        // skip
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'mount-allowlist.json is not group/world writable',
      failed: () => 'mount-allowlist.json is writable by other users',
      fixable: true,
      fixDescription: 'chmod 600 mount-allowlist.json',
    });
  },

  async fix(ctx) {
    let fixed = 0;
    for (const config of ctx.configs) {
      if (!config.filePath.endsWith('mount-allowlist.json')) continue;
      try {
        await chmodFile(config.filePath, 0o600);
        fixed++;
      } catch {
        // skip
      }
    }
    return {
      checkId: 'NC-002',
      applied: fixed > 0,
      message: fixed > 0 ? `Set 0600 on mount-allowlist.json` : 'No allowlist file to fix',
    };
  },
});
