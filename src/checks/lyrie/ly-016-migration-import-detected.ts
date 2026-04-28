import { join } from 'node:path';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

interface MigrationManifest {
  platform?: string;
  itemsMigrated?: number;
}

export const ly016 = defineCheck({
  id: 'LY-016',
  name: 'Cross-Agent Migration Detected',
  category: 'lyrie',
  severity: 'info',
  description: 'Surface ~/.lyrie/migrations/*.json manifests — Lyrie can import memory/skills/config from OpenClaw, Hermes, AutoGPT, NanoClaw, ZeroClaw, Nanobot, etc. The source agent\'s threat exposure (compromised memory, planted skills) carries over into Lyrie.',
  supportedAgents: ['lyrie'],

  async run(ctx, h) {
    const dir = join(ctx.installation.installDir, 'migrations');
    if (!(await ctx.fs.access(dir))) return h.passed('No migrations recorded');

    const evidence: Evidence[] = [];
    try {
      const entries = await ctx.fs.readdir(dir);
      const manifests = entries.filter(name => name.endsWith('.json'));
      const platforms = new Set<string>();

      for (const name of manifests) {
        try {
          const raw = await ctx.fs.readFile(join(dir, name));
          const data = JSON.parse(raw) as MigrationManifest;
          if (data.platform) platforms.add(data.platform);
        } catch {
          // skip malformed
        }
      }

      if (platforms.size > 0) {
        evidence.push({
          file: dir,
          detail: `Memory imported from: ${[...platforms].sort().join(', ')} — review the source agent(s) for compromise; their threat exposure transfers to Lyrie`,
        });
      }
    } catch {
      // skip
    }

    return h.fromEvidence(evidence, {
      passed: 'No cross-agent imports detected',
      failed: () => 'Cross-agent imports present (informational)',
      fixDescription: 'Scan the source agent(s) (e.g. `vaso scan -a openclaw`) — anything they were exposed to is now reachable from Lyrie\'s memory',
    });
  },
});
