import { stat } from 'node:fs/promises';
import type { CheckModule, ScanContext, CheckResult, Evidence } from '../../core/types.js';

export const run004: CheckModule = {
  id: 'RUN-004',
  name: 'Docker Security',
  category: 'runtime',
  severity: 'warning',
  description: 'Check Docker socket permissions and container security',
  supportedPlatforms: ['darwin', 'linux'],

  async run(_ctx: ScanContext): Promise<CheckResult> {
    const evidence: Evidence[] = [];

    // Check Docker socket permissions
    try {
      const stats = await stat('/var/run/docker.sock');
      const mode = stats.mode & 0o777;

      // Warn if world-readable/writable
      if (mode & 0o006) {
        evidence.push({
          file: '/var/run/docker.sock',
          detail: `Docker socket permissions: ${mode.toString(8)} — world-accessible`,
        });
      }
    } catch {
      // Docker not installed or no socket
    }

    return {
      id: 'RUN-004',
      name: 'Docker Security',
      category: 'runtime',
      severity: 'warning',
      passed: evidence.length === 0,
      message: evidence.length === 0
        ? 'Docker security checks passed (or Docker not installed)'
        : `Found ${evidence.length} Docker security issue(s)`,
      evidence: evidence.length > 0 ? evidence : undefined,
    };
  },
};
