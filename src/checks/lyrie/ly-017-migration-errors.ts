import { join } from 'node:path';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { lyrieStateDir } from '../../adapters/lyrie.js';

export const ly017 = defineCheck({
  id: 'LY-017',
  name: 'Cross-Agent Migration Errors',
  category: 'lyrie',
  severity: 'warning',
  description: 'Detect ~/.lyrie/migrations/*.json manifests with non-empty errors[] or success=false — a partially imported state may leave dangling references or half-imported memory and skills.',
  supportedAgents: ['lyrie'],

  async run(ctx, h) {
    const dir = join(lyrieStateDir(ctx.fs), 'migrations');
    if (!(await ctx.fs.access(dir))) return h.passed('No migrations recorded');

    const evidence: Evidence[] = [];
    try {
      const entries = await ctx.fs.readdir(dir);
      for (const name of entries.filter(n => n.endsWith('.json'))) {
        const path = join(dir, name);
        try {
          const data = JSON.parse(await ctx.fs.readFile(path)) as Record<string, unknown> | null;
          if (!data || typeof data !== 'object') continue;
          const failed = data.success === false;
          const errors = Array.isArray(data.errors) ? data.errors.length : 0;
          if (failed || errors > 0) {
            const platform = typeof data.platform === 'string' ? data.platform : 'unknown';
            evidence.push({
              file: path,
              detail: `Migration from "${platform}" reported ${errors} error(s)${failed ? ' and was marked unsuccessful' : ''}`,
            });
          }
        } catch {
          // skip malformed
        }
      }
    } catch {
      // skip
    }

    return h.fromEvidence(evidence, {
      passed: 'All recorded migrations completed cleanly',
      failed: () => 'One or more migrations completed with errors',
      fixDescription: 'Inspect the manifest errors, then re-run `bun run migrate --from <platform>` in the Lyrie checkout or remove the partially imported skills/memory',
    });
  },
});
