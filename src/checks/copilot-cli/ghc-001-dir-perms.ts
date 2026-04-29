import { join } from 'node:path';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

const PROTECTED_FILES = [
  'config.json',
  'settings.json',
  'lsp-config.json',
  'command-history-state.json',
];
const PROTECTED_DIRS = ['.', 'session-state'];

export const ghc001 = defineCheck({
  id: 'GHC-001',
  name: 'Copilot CLI Directory Permissions',
  category: 'coding-agent',
  severity: 'critical',
  description: 'Verify ~/.copilot/, session-state/, and credential files are not group/world readable',
  supportedAgents: ['copilot-cli'],
  supportedPlatforms: ['darwin', 'linux'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    for (const subdir of PROTECTED_DIRS) {
      const path = subdir === '.' ? ctx.installation.installDir : join(ctx.installation.installDir, subdir);
      if (!(await ctx.fs.access(path))) continue;
      try {
        const stat = await ctx.fs.stat(path);
        const perms = stat.mode & 0o777;
        if ((perms & 0o077) !== 0) {
          evidence.push({
            file: path,
            snippet: `mode 0${perms.toString(8)}`,
            detail: `${subdir === '.' ? '~/.copilot/' : `${subdir}/`} is readable or writable by group/other — auth/session state may leak`,
          });
        }
      } catch {}
    }

    for (const filename of PROTECTED_FILES) {
      const filePath = join(ctx.installation.installDir, filename);
      if (!(await ctx.fs.access(filePath))) continue;
      try {
        const stat = await ctx.fs.stat(filePath);
        const perms = stat.mode & 0o777;
        if ((perms & 0o077) !== 0) {
          evidence.push({
            file: filePath,
            snippet: `mode 0${perms.toString(8)}`,
            detail: `${filename} is readable or writable by group/other`,
          });
        }
      } catch {}
    }

    return h.fromEvidence(evidence, {
      passed: 'Copilot CLI directory and config files are owner-only',
      failed: (n) => `Found ${n} Copilot CLI path(s) with overly permissive mode`,
      fixDescription: 'Run `chmod -R go-rwx ~/.copilot` to restrict access to the owner',
    });
  },
});
