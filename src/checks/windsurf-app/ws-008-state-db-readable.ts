import { join } from 'node:path';
import type { Evidence, Platform } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { markUnreachable, queryPermissions, readableByOthers } from '../../core/permissions.js';
import type { FSProvider } from '../../core/fs-provider.js';
import { editorUserDataDirs } from '../../adapters/windsurf.js';

/**
 * Per-OS editor user-data dirs (the adapter's, XDG-aware on Linux). Only
 * darwin/linux are probed — on other platforms the POSIX permission model
 * doesn't apply and the check skips.
 */
function userDataDirs(home: string, ctx: { platform: Platform; fs: FSProvider }): string[] | undefined {
  return ctx.platform === 'darwin' || ctx.platform === 'linux' ? editorUserDataDirs(home, ctx.fs) : undefined;
}

export const ws008 = defineCheck({
  id: 'WS-008',
  name: 'Windsurf Editor State DB Readable',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Verify that state.vscdb (ItemTable key windsurfAuthStatus holds the API key) is not readable by other users',
  supportedAgents: ['windsurf'],

  async run(ctx, h) {
    const dirs = userDataDirs(ctx.fs.homedir(), ctx);
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

    await markUnreachable(ctx.fs, evidence);
    return h.fromEvidence(evidence, {
      passed: 'Windsurf editor state DB has restricted permissions (or is absent)',
      failed: (n) => `Found ${n} editor state DB file(s) readable by other users`,
      fixDescription: 'Run `chmod 600` on state.vscdb under the Windsurf/Devin user-data dir',
    });
  },
});
