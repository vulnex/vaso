import { join } from 'node:path';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { queryPermissions, readableByOthers } from '../../core/permissions.js';

const EDITOR_DIR_NAMES = ['Windsurf', 'Devin'];

/**
 * Per-OS editor user-data dirs. Only darwin/linux are probed — on other
 * platforms the POSIX permission model doesn't apply and the check skips.
 */
function userDataDirs(home: string, platform: NodeJS.Platform): string[] | undefined {
  if (platform === 'darwin') {
    return EDITOR_DIR_NAMES.map(n => join(home, 'Library', 'Application Support', n));
  }
  if (platform === 'linux') {
    return EDITOR_DIR_NAMES.map(n => join(home, '.config', n));
  }
  return undefined;
}

export const ws008 = defineCheck({
  id: 'WS-008',
  name: 'Windsurf Editor State DB Readable',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Verify that state.vscdb (ItemTable key windsurfAuthStatus holds the API key) is not readable by other users',
  supportedAgents: ['windsurf'],

  async run(ctx, h) {
    const dirs = userDataDirs(ctx.fs.homedir(), ctx.platform);
    if (!dirs) {
      return h.passed('Editor state DB permission check not applicable on this platform');
    }

    const evidence: Evidence[] = [];
    for (const dir of dirs) {
      const dbPath = join(dir, 'User', 'globalStorage', 'state.vscdb');
      if (!(await ctx.fs.access(dbPath))) continue;
      try {
        const perms = await queryPermissions(ctx.fs, dbPath);
        if (perms === 'unsupported') continue;
        if (readableByOthers(perms)) {
          evidence.push({
            file: dbPath,
            snippet: `mode 0${perms.octal}`,
            detail: 'state.vscdb holds windsurfAuthStatus (API key) and is readable by group/other',
          });
        }
      } catch {
        // Can't stat — skip silently
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'Windsurf editor state DB has restricted permissions (or is absent)',
      failed: (n) => `Found ${n} editor state DB file(s) readable by other users`,
      fixDescription: 'Run `chmod 600` on state.vscdb under the Windsurf/Devin user-data dir',
    });
  },
});
