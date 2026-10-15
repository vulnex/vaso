import { join } from 'node:path';
import type { Evidence, ScanContext } from '../../core/types.js';
import { xdgConfigDir, xdgDataDir } from '../../adapters/opencode.js';
import { defineCheck } from '../../core/check-builder.js';
import { accessibleByOthers, markUnreachable, queryPermissions } from '../../core/permissions.js';
import { restrictFilesToOwner } from '../../remediation/config-writer.js';

export const opc001 = defineCheck({
  id: 'OPC-001',
  name: 'OpenCode Auth File Permissions',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Verify that ~/.local/share/opencode/auth.json is not readable by other users',
  supportedAgents: ['opencode'],
  supportedPlatforms: ['darwin', 'linux'],

  async run(ctx, h) {
    const paths = authPaths(ctx);
    const evidence: Evidence[] = [];
    for (const authPath of paths) {
      if (!(await ctx.fs.access(authPath))) continue;
      try {
        const perms = await queryPermissions(ctx.fs, authPath);
        // 'unsupported' (no evaluable permission model) → nothing to flag
        if (perms !== 'unsupported' && accessibleByOthers(perms)) {
          evidence.push({
            file: authPath,
            snippet: `mode 0${perms.octal}`,
            detail: 'auth.json is readable or writable by group/other — credentials may be exposed',
          });
        }
      } catch {
        // skip
      }
    }

    await markUnreachable(ctx.fs, evidence);
    return h.fromEvidence(evidence, {
      passed: 'OpenCode auth.json has restricted permissions',
      failed: () => 'OpenCode auth.json is over-permissive — restrict it to 0600',
      fixable: true,
      fixDescription: 'Remove group/other access from auth.json (chmod go-rwx ~/.local/share/opencode/auth.json)',
    });
  },

  async fix(ctx) {
    return restrictFilesToOwner('OPC-001', authPaths(ctx));
  },
});

/**
 * The scanning user's install follows $XDG_DATA_HOME (the adapter resolved
 * installDir from $XDG_CONFIG_HOME the same way); another user's is the
 * default layout next to their config dir. A project install has no auth.json.
 */
function authPaths(ctx: ScanContext): string[] {
  if (ctx.installation.agent !== 'opencode' || ctx.installation.profile === 'project') return [];
  const home = ctx.fs.homedir();
  const own = ctx.installation.installDir === xdgConfigDir(home, ctx.fs);
  return [join(own ? xdgDataDir(home, ctx.fs) : dataDirFromInstall(ctx.installation.installDir), 'auth.json')];
}

// installDir is the XDG config dir (e.g. ~/.config/opencode); auth.json lives
// in the parallel XDG data dir. Replace the trailing `.config/opencode` segment
// with `.local/share/opencode`. Falls back to the literal path if the pattern
// doesn't match — better to skip the check than to stat the wrong file.
function dataDirFromInstall(installDir: string): string {
  return installDir.replace(/\/\.?config\/opencode$/, '/.local/share/opencode');
}
