import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { CODING_AGENTS } from '../../core/types.js';
import { truncateSnippet } from '../../core/patterns.js';
import { agentExecutable, SUSPICIOUS_KEYWORDS } from './run-001-launch-agents.js';

/** The command of a crontab line: after the five schedule fields, or an `@reboot`-style nickname. */
export function cronCommand(line: string): string[] {
  const parts = line.trim().split(/\s+/);
  if (parts[0]?.startsWith('@')) return parts.slice(1);
  // fewer fields: an environment assignment (PATH=…), not a job
  return parts.length >= 6 ? parts.slice(5) : [];
}

export const run002 = defineCheck({
  id: 'RUN-002',
  name: 'Suspicious Cron Entries',
  category: 'runtime',
  severity: 'warning',
  description: 'Check for cron entries referencing agent paths',
  excludedAgents: CODING_AGENTS,
  supportedPlatforms: ['darwin', 'linux'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    try {
      const crontab = ctx.fs.execSync('crontab', ['-l'], { timeout: 5000 });
      const lines = crontab.split('\n');

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i].trim();
        if (!line || line.startsWith('#')) continue;

        const lower = line.toLowerCase();
        const keyword = SUSPICIOUS_KEYWORDS.find(k => lower.includes(k));
        if (!keyword) continue;
        // A job that runs this installation (its CLI, another copy of it, or
        // a program in its install dir / CLI package) is the agent's own
        // schedule, as RUN-001 judges services: info. Anything else naming
        // an agent is a warning — an agent-named program elsewhere proves
        // nothing. Another detected agent's own job is left to that agent
        // by the engine (dedupeOwnPersistence), never dropped here.
        const command = cronCommand(line);
        const own = command.length > 0 ? await agentExecutable(command, ctx) : undefined;
        const item: Evidence = own
          ? { file: 'crontab', line: i + 1, snippet: truncateSnippet(line, 120), detail: `Cron entry runs an installed agent — ${own}`, mitigated: true }
          : { file: 'crontab', line: i + 1, snippet: truncateSnippet(line, 120), detail: `Cron entry references "${keyword}", not the installed agent's own program` };
        evidence.push(item);
      }
    } catch {
      // No crontab or access denied
    }

    const suspicious = evidence.filter(e => !e.mitigated).length;
    return h.fromEvidence(evidence, {
      passed: 'No suspicious cron entries found',
      failed: (n) => suspicious === 0
        ? `Found ${n} cron entry/entries — all run an installed agent`
        : `Found ${suspicious} suspicious cron entry/entries`,
    });
  },
});
