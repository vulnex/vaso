import { join } from 'node:path';
import type { Evidence, ScanContext } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { accessibleByOthers, markUnreachable, queryPermissions } from '../../core/permissions.js';
import { restrictFilesToOwner } from '../../remediation/config-writer.js';
import { DATA_FILES, USER_DATA_FILES } from '../../adapters/grok-bot.js';
import { dataFile, userDataDir } from './shared.js';

function targets(ctx: ScanContext): { path: string; level: 'critical' | 'warning'; holds: string }[] {
  const userData = userDataDir(ctx);
  return [
    { path: dataFile(ctx, DATA_FILES.credential), level: 'critical', holds: 'the local-exec credential (the channel the cloud agent runs commands through)' },
    { path: dataFile(ctx, DATA_FILES.connection), level: 'critical', holds: 'the local-exec backend connection token' },
    { path: join(userData, USER_DATA_FILES.secrets), level: 'critical', holds: 'Cursor access/refresh tokens and the local-exec seal key' },
    { path: join(userData, USER_DATA_FILES.userSecrets), level: 'critical', holds: 'user-defined secrets shared with the cloud computer' },
    { path: dataFile(ctx, DATA_FILES.approvals), level: 'warning', holds: 'pending local-tool approvals' },
    { path: join(userData, USER_DATA_FILES.cookies), level: 'warning', holds: 'the signed-in session cookies' },
  ];
}

export const gb007 = defineCheck({
  id: 'GB-007',
  name: 'Grok Bot Credential File Permissions',
  category: 'coding-agent',
  severity: 'critical',
  description: 'Verify Grok Bot\'s local-exec credential and connection files, sand-secrets.json, user-secrets.json, approvals and session cookies are not accessible to other local users (the app writes them 0600)',
  supportedAgents: ['grok-bot'],
  supportedPlatforms: ['darwin', 'linux'],

  async run(ctx, h) {
    const critical: Evidence[] = [];
    const warning: Evidence[] = [];
    for (const t of targets(ctx)) {
      try {
        if (!(await ctx.fs.access(t.path))) continue;
        const perms = await queryPermissions(ctx.fs, t.path);
        if (perms === 'unsupported' || !accessibleByOthers(perms)) continue;
        (t.level === 'critical' ? critical : warning).push({ file: t.path, snippet: `mode 0${perms.octal}`, detail: `Holds ${t.holds} and is accessible to group or other users` });
      } catch {
        // can't stat — skip
      }
    }
    await markUnreachable(ctx.fs, critical);
    await markUnreachable(ctx.fs, warning);
    return h.fromEvidence([...critical, ...warning], {
      passed: 'Grok Bot credential files are owner-only',
      failed: (n) => `Found ${n} Grok Bot credential file(s) accessible beyond the owner`,
      severity: critical.some(e => !e.mitigated) || warning.length === 0 ? undefined : 'warning',
      fixable: true,
      fixDescription: 'Remove group/other access (chmod go-rwx) from the Grok Bot credential files; sign out and back in if exposure is suspected',
    });
  },

  async fix(ctx) {
    return restrictFilesToOwner('GB-007', targets(ctx).map(t => t.path));
  },
});
