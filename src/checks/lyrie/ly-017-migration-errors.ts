import { join } from 'node:path';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

interface MigrationManifest {
  platform?: string;
  errors?: string[];
  warnings?: string[];
  success?: boolean;
}

export const ly017 = defineCheck({
  id: 'LY-017',
  name: 'Cross-Agent Migration Errors',
  category: 'lyrie',
  severity: 'warning',
  description: 'Detect ~/.lyrie/migrations/*.json manifests with non-empty errors[] or success=false — a partially imported state may leave dangling references, corrupt memory, or skipped Shield-gating.',
  supportedAgents: ['lyrie'],

  async run(ctx, h) {
    const dir = join(ctx.installation.installDir, 'migrations');
    if (!(await ctx.fs.access(dir))) return h.passed('No migrations recorded');

    const evidence: Evidence[] = [];
    try {
      const entries = await ctx.fs.readdir(dir);
      for (const name of entries.filter(n => n.endsWith('.json'))) {
        const path = join(dir, name);
        try {
          const raw = await ctx.fs.readFile(path);
          const data = JSON.parse(raw) as MigrationManifest;
          const failed = data.success === false;
          const hasErrors = Array.isArray(data.errors) && data.errors.length > 0;
          if (failed || hasErrors) {
            evidence.push({
              file: path,
              detail: `Migration from "${data.platform ?? 'unknown'}" reported ${data.errors?.length ?? 0} error(s)${failed ? ' and was marked unsuccessful' : ''}`,
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
      fixDescription: 'Re-run `lyrie migrate --from <platform>` for the affected import, or clear the partial state from ~/.lyrie/memory/lyrie-memory.db',
    });
  },
});
