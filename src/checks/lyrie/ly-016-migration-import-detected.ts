import { join } from 'node:path';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { lyrieStateDir } from '../../adapters/lyrie.js';

export const ly016 = defineCheck({
  id: 'LY-016',
  name: 'Cross-Agent Migration Detected',
  category: 'lyrie',
  severity: 'info',
  description: 'Surface ~/.lyrie/migrations/*.json manifests written by `bun run migrate --from <platform>` — Lyrie imports memory, skills and config from OpenClaw, Hermes, AutoGPT, NanoClaw, ZeroClaw, Nanobot, etc. The source agent\'s threat exposure (poisoned memory, planted skills) carries over into Lyrie.',
  supportedAgents: ['lyrie'],

  async run(ctx, h) {
    const dir = join(lyrieStateDir(ctx.fs), 'migrations');
    if (!(await ctx.fs.access(dir))) return h.passed('No migrations recorded');

    const evidence: Evidence[] = [];
    try {
      const entries = await ctx.fs.readdir(dir);
      const platforms = new Set<string>();

      for (const name of entries.filter(n => n.endsWith('.json'))) {
        try {
          const data = JSON.parse(await ctx.fs.readFile(join(dir, name))) as Record<string, unknown> | null;
          if (data && typeof data.platform === 'string' && data.platform) platforms.add(data.platform);
        } catch {
          // skip malformed
        }
      }

      if (platforms.size > 0) {
        evidence.push({
          file: dir,
          detail: `Data imported from: ${[...platforms].sort().join(', ')} — review the source agent(s); their exposure transfers to Lyrie`,
        });
      }
    } catch {
      // skip
    }

    return h.fromEvidence(evidence, {
      passed: 'No cross-agent imports detected',
      failed: () => 'Cross-agent imports present (informational)',
      fixDescription: 'Scan the source agent(s) (e.g. `vaso scan -a nanobot`) and review the imported skills in ~/.lyrie/skills',
    });
  },
});
