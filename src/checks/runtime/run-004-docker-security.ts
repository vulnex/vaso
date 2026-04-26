import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { CODING_AGENTS } from '../../core/types.js';

export const run004 = defineCheck({
  id: 'RUN-004',
  name: 'Docker Security',
  category: 'runtime',
  severity: 'warning',
  description: 'Check Docker socket permissions and container security',
  excludedAgents: CODING_AGENTS,
  supportedPlatforms: ['darwin', 'linux'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    try {
      const stats = await ctx.fs.stat('/var/run/docker.sock');
      const mode = stats.mode & 0o777;
      if (mode & 0o006) {
        evidence.push({
          file: '/var/run/docker.sock',
          detail: `Docker socket permissions: ${mode.toString(8)} — world-accessible`,
        });
      }
    } catch {
      // Docker not installed or no socket
    }

    return h.fromEvidence(evidence, {
      passed: 'Docker security checks passed (or Docker not installed)',
      failed: (n) => `Found ${n} Docker security issue(s)`,
    });
  },
});
