import { join } from 'node:path';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { markUnreachable, queryPermissions, readableByOthers } from '../../core/permissions.js';

// Written with no explicit mode upstream, so they follow the umask.
const STATE_FILES: Array<[string, string]> = [
  ['memory.sqlite', 'long-term memory (profile facts, notes, lessons)'],
  ['sessions.sqlite', 'full conversation transcripts'],
  ['tasks.sqlite', 'scheduled task prompts and results'],
  ['config.json', 'agent settings (and any secrets placed there)'],
  ['webhook-sessions.json', 'webhook session mappings'],
  ['telegram-session.json', 'Telegram channel session state'],
  ['discord-session.json', 'Discord channel session state'],
];

export const at011 = defineCheck({
  id: 'AT-011',
  name: 'Atomic Agent Private State Readable by Others',
  category: 'atomic-agent',
  severity: 'warning',
  description: 'Memory, session and task databases, config.json, channel session files, or unredacted tool traces (traces/*.ndjson — prompts, tool arguments and outputs verbatim) under the state dir are group/world-readable. Atomic Agent creates them without an explicit mode, so they inherit the umask.',
  supportedAgents: ['atomic-agent'],
  supportedPlatforms: ['darwin', 'linux'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    const stateDir = ctx.installation.installDir;
    const candidates: Array<[string, string]> = STATE_FILES.map(([rel, holds]) => [join(stateDir, rel), holds]);
    try {
      for (const e of await ctx.fs.readdirEntries(join(stateDir, 'traces'))) {
        if (!e.isDirectory && e.name.endsWith('.ndjson')) {
          candidates.push([join(stateDir, 'traces', e.name), 'an unredacted tool trace (prompts, tool arguments and outputs)']);
        }
      }
    } catch {
      // No traces dir
    }

    for (const [file, holds] of candidates) {
      try {
        if (!(await ctx.fs.access(file))) continue;
        const perms = await queryPermissions(ctx.fs, file);
        if (perms === 'unsupported' || !readableByOthers(perms)) continue;
        evidence.push({
          file,
          snippet: `mode 0${perms.octal}`,
          detail: `Holds ${holds} and is readable by group or other users`,
        });
      } catch {
        // Can't stat — skip
      }
    }
    await markUnreachable(ctx.fs, evidence);
    return h.fromEvidence(evidence, {
      passed: 'Atomic Agent private state is owner-only',
      failed: (n) => `${n} Atomic Agent state file(s) readable by other users`,
      fixDescription: 'Run `chmod 700 ~/.atomic-agent && chmod 600 ~/.atomic-agent/*.sqlite ~/.atomic-agent/*.json ~/.atomic-agent/traces/*` (or set umask 077 before starting the agent)',
    });
  },
});
