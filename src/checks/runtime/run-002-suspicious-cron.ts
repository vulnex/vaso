import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { CODING_AGENTS } from '../../core/types.js';
import { truncateSnippet } from '../../core/patterns.js';
import { agentExecutable, keep, SUSPICIOUS_KEYWORDS } from './run-001-launch-agents.js';

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
        // A job that runs an installed agent (its CLI, or an agent-named
        // program under a standard install root) is the agent's own
        // schedule, as RUN-001 judges services; reported once, under that
        // agent, as info
        const command = cronCommand(line);
        const own = command.length > 0 ? agentExecutable(command, keyword, ctx) : undefined;
        const item: Evidence = own
          ? { file: 'crontab', line: i + 1, snippet: truncateSnippet(line, 120), detail: `Cron entry runs an installed agent — ${own}`, mitigated: true }
          : { file: 'crontab', line: i + 1, snippet: truncateSnippet(line, 120), detail: `Cron entry references "${keyword}", not a recognized agent install location` };
        keep(evidence, line, ctx, item);
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
