import { join } from 'node:path';
import type { Evidence, ScanContext } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { markUnreachable, queryPermissions, readableByOthers } from '../../core/permissions.js';
import { restrictFilesToOwner } from '../../remediation/config-writer.js';
import { DATA_FILES, USER_DATA_FILES } from '../../adapters/grok-bot.js';
import { dataFile, userDataDir } from './shared.js';

interface Target {
  path: string;
  level: 'warning' | 'info';
  holds: string;
  dir?: boolean;
}

async function targets(ctx: ScanContext): Promise<Target[]> {
  const userData = await userDataDir(ctx);
  return [
    // Data root and user-data dir themselves: the app creates them 0700
    { path: ctx.installation.installDir, level: 'warning', holds: 'Grok Bot settings, approvals and local-exec state', dir: true },
    { path: userData, level: 'warning', holds: 'the Grok Bot session profile and secret stores', dir: true },
    // Blob names encode the account id; blobs hold transcript replicas and the send journal
    { path: join(userData, USER_DATA_FILES.clientPersistence), level: 'warning', holds: 'cached transcripts and the send journal (names reveal the account id)', dir: true },
    // Written without an explicit mode (umask 0664 on Ubuntu)
    { path: dataFile(ctx, DATA_FILES.daemonState), level: 'info', holds: 'local-exec daemon state (pid, key id, generation)' },
    { path: dataFile(ctx, DATA_FILES.daemonLog), level: 'info', holds: 'the local-exec daemon log (connection history with the cloud agent)' },
    { path: join(userData, USER_DATA_FILES.statsig), level: 'info', holds: 'feature-flag bootstrap data tied to the account' },
    { path: join(userData, USER_DATA_FILES.reliability), level: 'info', holds: 'the install id and reliability telemetry outbox', dir: true },
  ];
}

export const gb008 = defineCheck({
  id: 'GB-008',
  name: 'Grok Bot Runtime Data Readable by Others',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Check that Grok Bot\'s data root, user-data profile and client state (cached transcripts, local-exec daemon log and state, telemetry outbox) are not readable by other local users — several are created with the default umask',
  supportedAgents: ['grok-bot'],
  supportedPlatforms: ['darwin', 'linux'],

  async run(ctx, h) {
    const warning: Evidence[] = [];
    const info: Evidence[] = [];
    const all = await targets(ctx);
    const files = new Set(all.filter(t => !t.dir).map(t => t.path));
    for (const t of all) {
      try {
        if (!(await ctx.fs.access(t.path))) continue;
        // A regular file where the app expects a directory holds none of its data
        if (t.dir && !(await ctx.fs.stat(t.path)).isDirectory()) continue;
        const perms = await queryPermissions(ctx.fs, t.path);
        if (perms === 'unsupported' || !readableByOthers(perms)) continue;
        (t.level === 'warning' ? warning : info).push({ file: t.path, snippet: `mode 0${perms.octal}`, detail: `${t.dir ? 'Directory with' : 'Holds'} ${t.holds} — readable by group or other users` });
      } catch {
        // can't stat — skip
      }
    }
    await markUnreachable(ctx.fs, warning);
    await markUnreachable(ctx.fs, info);
    return h.fromEvidence([...warning, ...info], {
      passed: 'Grok Bot runtime data is owner-only',
      failed: (n) => `Found ${n} Grok Bot data path(s) readable by other users`,
      severity: warning.some(e => !e.mitigated) || info.length === 0 ? undefined : 'info',
      fixable: info.some(e => files.has(e.file ?? '')),
      fixDescription: 'chmod go-rwx the flagged Grok Bot files and directories (vaso fix restricts the files; directories need a manual chmod 700)',
    });
  },

  async fix(ctx) {
    return restrictFilesToOwner('GB-008', (await targets(ctx)).filter(t => !t.dir).map(t => t.path));
  },
});
