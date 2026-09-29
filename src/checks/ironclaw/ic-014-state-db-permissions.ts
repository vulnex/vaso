import { dirname, join } from 'node:path';
import type { Evidence } from '../../core/types.js';
import type { FSProvider } from '../../core/fs-provider.js';
import { defineCheck } from '../../core/check-builder.js';
import { markUnreachable, queryPermissions } from '../../core/permissions.js';
import { REBORN_DB_FILE, REBORN_STORAGE_SUBDIRS } from '../../adapters/ironclaw.js';
import { isLegacy } from './layout.js';

/*
 * The state database holds conversation threads, agent memory, extension
 * installs and the (encrypted) secrets store.
 * 1.x: `<reborn home>/<storage>/reborn-local-dev.db` (+ -wal/-shm, libSQL).
 * 0.x: `~/.ironclaw/ironclaw.db` (+ -wal/-shm).
 * libSQL creates them with the process umask (typically 0644), so whether
 * other local users can read them depends on the parent directories — the
 * finding is downgraded when an ancestor blocks traversal. Only world access
 * counts: the group is normally the owner's private group.
 */

async function worldBlocked(fs: FSProvider, start: string): Promise<boolean> {
  for (let dir = start; ; dir = dirname(dir)) {
    try {
      const q = await queryPermissions(fs, dir);
      if (q !== 'unsupported' && !q.worldExec) return true;
    } catch {
      // unknown ancestor — treat as traversable
    }
    if (dirname(dir) === dir) return false;
  }
}

export const ic014 = defineCheck({
  id: 'IC-014',
  name: 'State Database World-Readable',
  category: 'ironclaw',
  severity: 'warning',
  description: 'Check that the IronClaw state database (conversations, memory, secrets store) is not world-readable (the group is typically the owner\'s private group)',
  supportedAgents: ['ironclaw'],

  async run(ctx, h) {
    const dir = ctx.installation.installDir;
    const dbs = isLegacy(ctx)
      ? [join(dir, 'ironclaw.db')]
      : REBORN_STORAGE_SUBDIRS.map(sub => join(dir, sub, REBORN_DB_FILE));

    const evidence: Evidence[] = [];
    for (const db of dbs) {
      for (const path of [db, `${db}-wal`]) {
        try {
          if (!(await ctx.fs.access(path))) continue;
          const perms = await queryPermissions(ctx.fs, path);
          if (perms !== 'unsupported' && perms.worldRead) {
            evidence.push({
              file: path,
              snippet: `mode 0${perms.octal ?? '?'}`,
              detail: 'State database is world-readable — conversation history and agent memory are exposed to other local users',
            });
          }
        } catch {
          // can't stat — skip
        }
      }
    }

    await markUnreachable(ctx.fs, evidence);
    // Only world access counts here, so a parent that blocks world traversal
    // is enough — markUnreachable also demands a group barrier.
    for (const e of evidence) {
      if (!e.mitigated && e.file && await worldBlocked(ctx.fs, dirname(e.file))) {
        e.mitigated = true;
        e.detail = `${e.detail} — mitigated: a parent directory blocks world traversal`;
      }
    }
    return h.fromEvidence(evidence, {
      passed: 'State database is not world-readable',
      failed: (n) => `${n} IronClaw state database file(s) world-readable`,
      fixDescription: 'chmod 600 the database files (and 700 their directory); set a restrictive umask (077) for the IronClaw service',
    });
  },
});
