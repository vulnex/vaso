import { join } from 'node:path';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { accessibleByOthers, markUnreachable, queryPermissions } from '../../core/permissions.js';
import type { ScanContext } from '../../core/types.js';
import { restrictFilesToOwner } from '../../remediation/config-writer.js';

const SENSITIVE_FILES = [
  'credentials.json',
  'auth.json',
];

const SENSITIVE_DIR_GLOBS = [
  'mcp-tokens',
];

/** The credential files HM-003 inspects: fixed names plus mcp-tokens/*.json. */
async function credentialFiles(ctx: ScanContext): Promise<string[]> {
  const installDir = ctx.installation.installDir;
  const files = SENSITIVE_FILES.map(name => join(installDir, name));
  for (const dirName of SENSITIVE_DIR_GLOBS) {
    const dirPath = join(installDir, dirName);
    try {
      for (const entry of await ctx.fs.readdirEntries(dirPath)) {
        if (entry.isFile && entry.name.endsWith('.json')) files.push(join(dirPath, entry.name));
      }
    } catch {
      // Dir doesn't exist — skip
    }
  }
  return files;
}

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
    const checkPerms = async (filePath: string): Promise<void> => {
      try {
        const stat = await ctx.fs.stat(filePath);
        if (!stat.isFile()) return;
        const perms = await queryPermissions(ctx.fs, filePath);
        if (perms !== 'unsupported' && accessibleByOthers(perms)) {
          evidence.push({
            file: filePath,
            snippet: `mode 0${perms.octal}`,
            detail: 'Credential file readable by group or other users',
          });
        }
      } catch {
        // Path doesn't exist — skip
      }
    };

    for (const file of await credentialFiles(ctx)) await checkPerms(file);

    await markUnreachable(ctx.fs, evidence);
    return h.fromEvidence(evidence, {
      passed: 'Hermes credential files have restricted permissions',
      failed: (n) => `Found ${n} Hermes credential file(s) with over-permissive mode`,
      fixable: true,
      fixDescription: 'Remove group/other access from ~/.hermes/credentials.json, auth.json and mcp-tokens/*.json (whichever exist)',
    });
  },

  async fix(ctx) {
    return restrictFilesToOwner('HM-003', await credentialFiles(ctx));
  },
});
