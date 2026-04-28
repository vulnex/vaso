import { join } from 'node:path';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

const STALE_HOURS = 24;

interface EditPlan {
  createdAt?: string;
  requestedAt?: string;
  unifiedDiff?: string;
}

export const ly012 = defineCheck({
  id: 'LY-012',
  name: 'Stale Pending Edit Approvals',
  category: 'lyrie',
  severity: 'warning',
  description: 'Detect pending diff-view edits older than 24 hours — long queues mean operator inattention; old plans rebased against drifted file state apply with stale beforeHash failures or, worse, unintended changes.',
  supportedAgents: ['lyrie'],

  async run(ctx, h) {
    const path = join(ctx.installation.installDir, 'edits.json');
    if (!(await ctx.fs.access(path))) return h.passed('edits.json not present');

    const evidence: Evidence[] = [];
    try {
      const raw = await ctx.fs.readFile(path);
      const data = JSON.parse(raw) as { pending?: EditPlan[] };
      const pending = Array.isArray(data.pending) ? data.pending : [];
      const cutoff = Date.now() - STALE_HOURS * 60 * 60 * 1000;

      const stale = pending.filter(p => {
        const ts = Date.parse(p.createdAt ?? p.requestedAt ?? '');
        return Number.isFinite(ts) && ts < cutoff;
      });

      if (stale.length > 0) {
        evidence.push({
          file: path,
          detail: `${stale.length} pending edit plan(s) older than ${STALE_HOURS} hours — apply or discard before applying against drifted file state`,
        });
      }
    } catch {
      // Malformed JSON or read error
    }

    return h.fromEvidence(evidence, {
      passed: 'No stale pending edit approvals',
      failed: () => 'Stale pending edit approvals detected',
      fixDescription: 'Review pending edits with `lyrie edits list` and approve or discard them',
    });
  },
});
