import { join } from 'node:path';
import type { Evidence, ScanContext } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { queryPermissions, readableByOthers } from '../../core/permissions.js';

/**
 * Resolve credentials.toml the same way the adapter does: XDG data dir on
 * POSIX, %APPDATA%\devin on Windows — via ctx.fs so remote/snapshot
 * providers resolve against the scanned host, not the scanner.
 */
function credentialsPath(ctx: ScanContext): string {
  const fs = ctx.fs;
  const home = fs.homedir();
  if (fs.platform === 'win32') {
    const appData = fs.getEnv('APPDATA');
    const base = appData?.trim() ? appData : join(home, 'AppData', 'Roaming');
    return join(base, 'devin', 'credentials.toml');
  }
  const xdgData = fs.getEnv('XDG_DATA_HOME');
  const base = xdgData?.trim() ? xdgData : join(home, '.local', 'share');
  return join(base, 'devin', 'credentials.toml');
}

export const dev002 = defineCheck({
  id: 'DEV-002',
  name: 'Devin Credentials File Permissions',
  category: 'coding-agent',
  severity: 'critical',
  description: 'Verify that credentials.toml (persistent non-expiring Devin API token) is not readable by other users',
  supportedAgents: ['devin'],

  async run(ctx, h) {
    // credentials.toml is per-user; the project-scoped installation would
    // otherwise re-report the same file.
    if (ctx.installation.profile === 'project') {
      return h.passed('credentials.toml is user-level — evaluated on the user installation');
    }

    const credPath = credentialsPath(ctx);
    if (!(await ctx.fs.access(credPath))) {
      return h.passed('Devin credentials.toml not present');
    }

    const evidence: Evidence[] = [];
    try {
      const perms = await queryPermissions(ctx.fs, credPath);
      if (perms === 'unsupported') {
        // No capable permission provider on this platform — skip cleanly.
        return h.passed('Permission evaluation not supported on this platform — skipping credentials.toml check');
      }
      if (readableByOthers(perms)) {
        evidence.push({
          file: credPath,
          snippet: `mode 0${perms.octal}`,
          detail: 'credentials.toml is readable by group/other — the stored Devin API token never expires, so exposure is permanent until manually revoked',
        });
      }
    } catch {
      // Can't stat — skip silently
    }

    return h.fromEvidence(evidence, {
      passed: 'Devin credentials.toml has restricted permissions',
      failed: () => 'Devin credentials.toml is readable by other users — the API token it holds never expires',
      fixDescription: 'Run `chmod 600 ~/.local/share/devin/credentials.toml` and rotate the token if exposure is suspected',
    });
  },
});
