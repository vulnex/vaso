import type { Evidence } from '../../core/types.js';
import { join } from 'node:path';
import { defineCheck } from '../../core/check-builder.js';
import { chmodFile } from '../../remediation/config-writer.js';

const MEMORY_FILES = ['memory.json', 'conversations.db'];

export const oc006 = defineCheck({
  id: 'OC-006',
  name: 'Memory File Permissions',
  category: 'openclaw',
  severity: 'warning',
  description: 'Verify memory.json and conversations.db are not group/world-readable. These files contain conversation history with potential PII and embedded secrets.',
  supportedAgents: ['openclaw'],
  supportedPlatforms: ['darwin', 'linux'],

  async run(ctx, h) {
    if (ctx.installation.agentName) {
      return h.passed('Sub-agent installation; OC-006 only runs at top-level');
    }

    const evidence: Evidence[] = [];
    for (const name of MEMORY_FILES) {
      const filePath = join(ctx.installation.installDir, name);
      if (!(await ctx.fs.access(filePath))) continue;
      try {
        const stats = await ctx.fs.stat(filePath);
        const mode = stats.mode & 0o777;
        if (mode & 0o077) {
          evidence.push({
            file: filePath,
            detail: `Permissions: ${mode.toString(8)} — should be 600 (owner-only)`,
          });
        }
      } catch {
        // stat failure — skip
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'Memory files are owner-only (or absent)',
      failed: (n) => `${n} memory file${n === 1 ? '' : 's'} readable by group/other`,
      fixable: true,
      fixDescription: 'chmod 600 memory.json conversations.db',
    });
  },

  async fix(ctx) {
    let fixed = 0;
    for (const name of MEMORY_FILES) {
      const filePath = join(ctx.installation.installDir, name);
      try {
        await chmodFile(filePath, 0o600);
        fixed++;
      } catch {
        // File doesn't exist or chmod failed
      }
    }
    return {
      checkId: 'OC-006',
      applied: fixed > 0,
      message: fixed > 0 ? `Set 0600 on ${fixed} memory file${fixed === 1 ? '' : 's'}` : 'No memory files to fix',
    };
  },
});
