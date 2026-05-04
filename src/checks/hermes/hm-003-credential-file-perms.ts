import { join } from 'node:path';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

const SENSITIVE_FILES = [
  'credentials.json',
  'auth.json',
];

const SENSITIVE_DIR_GLOBS = [
  'mcp-tokens',
];

export const hm003 = defineCheck({
  id: 'HM-003',
  name: 'Hermes Credential File Over-Permissive Permissions',
  category: 'hermes',
  severity: 'critical',
  description: 'Detect ~/.hermes/credentials.json, ~/.hermes/auth.json, and ~/.hermes/mcp-tokens/*.json with mode wider than 0600.',
  supportedAgents: ['hermes'],
  supportedPlatforms: ['darwin', 'linux'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    const installDir = ctx.installation.installDir;

    const checkPerms = async (filePath: string): Promise<void> => {
      try {
        const stat = await ctx.fs.stat(filePath);
        if (!stat.isFile()) return;
        const perms = stat.mode & 0o777;
        if ((perms & 0o077) !== 0) {
          evidence.push({
            file: filePath,
            snippet: `mode 0${perms.toString(8)}`,
            detail: 'Credential file readable by group or other users',
          });
        }
      } catch {
        // Path doesn't exist — skip
      }
    };

    for (const name of SENSITIVE_FILES) {
      await checkPerms(join(installDir, name));
    }

    for (const dirName of SENSITIVE_DIR_GLOBS) {
      const dirPath = join(installDir, dirName);
      try {
        const entries = await ctx.fs.readdirEntries(dirPath);
        for (const entry of entries) {
          if (!entry.isFile) continue;
          if (!entry.name.endsWith('.json')) continue;
          await checkPerms(join(dirPath, entry.name));
        }
      } catch {
        // Dir doesn't exist — skip
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'Hermes credential files have restricted permissions',
      failed: (n) => `Found ${n} Hermes credential file(s) with over-permissive mode`,
      fixDescription: 'Run `chmod 600 ~/.hermes/credentials.json ~/.hermes/auth.json ~/.hermes/mcp-tokens/*.json` (whichever exist)',
    });
  },
});
