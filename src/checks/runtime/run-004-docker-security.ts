import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { queryPermissions } from '../../core/permissions.js';
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
      const perms = await queryPermissions(ctx.fs, '/var/run/docker.sock');
      if (perms !== 'unsupported' && (perms.worldRead || perms.worldWrite)) {
        evidence.push({
          file: '/var/run/docker.sock',
          detail: `Docker socket permissions: ${perms.octal} — world-accessible`,
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
