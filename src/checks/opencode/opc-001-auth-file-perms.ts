import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

export const opc001 = defineCheck({
  id: 'OPC-001',
  name: 'OpenCode Auth File Permissions',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Verify that ~/.local/share/opencode/auth.json is not readable by other users',
  supportedAgents: ['opencode'],
  supportedPlatforms: ['darwin', 'linux'],

  async run(ctx, h) {
    const paths = ctx.installation.agent === 'opencode'
      ? [`${dataDirFromInstall(ctx.installation.installDir)}/auth.json`]
      : [];

    const evidence: Evidence[] = [];
    for (const authPath of paths) {
      if (!(await ctx.fs.access(authPath))) continue;
      try {
        const stat = await ctx.fs.stat(authPath);
        const perms = stat.mode & 0o777;
        if ((perms & 0o077) !== 0) {
          evidence.push({
            file: authPath,
            snippet: `mode 0${perms.toString(8)}`,
            detail: 'auth.json is readable or writable by group/other — credentials may be exposed',
          });
        }
      } catch {
        // skip
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'OpenCode auth.json has restricted permissions',
      failed: () => 'OpenCode auth.json is over-permissive — restrict it to 0600',
      fixDescription: 'Run `chmod 600 ~/.local/share/opencode/auth.json` to restrict access to the owner',
    });
  },
});

// installDir is the XDG config dir (e.g. ~/.config/opencode); auth.json lives
// in the parallel XDG data dir. Replace the trailing `.config/opencode` segment
// with `.local/share/opencode`. Falls back to the literal path if the pattern
// doesn't match — better to skip the check than to stat the wrong file.
function dataDirFromInstall(installDir: string): string {
  return installDir.replace(/\/\.?config\/opencode$/, '/.local/share/opencode');
}
