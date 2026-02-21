import { stat } from 'node:fs/promises';
import { join } from 'node:path';
import type { CheckModule, ScanContext, CheckResult } from '../../core/types.js';

export const zc013: CheckModule = {
  id: 'ZC-013',
  name: '.secret_key Permissions',
  category: 'zeroclaw',
  severity: 'critical',
  description: 'Check if .secret_key file has overly permissive file permissions',
  supportedAgents: ['zeroclaw'],
  supportedPlatforms: ['linux', 'darwin'],

  async run(ctx: ScanContext): Promise<CheckResult> {
    const evidence = [];
    const keyPath = join(ctx.installation.installDir, '.secret_key');
    try {
      const stats = await stat(keyPath);
      const mode = stats.mode & 0o777;
      if (mode !== 0o600) {
        evidence.push({
          file: keyPath,
          detail: `File permissions are ${mode.toString(8)} — should be 600`,
        });
      }
    } catch {
      // File doesn't exist — not a finding
    }
    return {
      id: 'ZC-013',
      name: '.secret_key Permissions',
      category: 'zeroclaw',
      severity: 'critical',
      passed: evidence.length === 0,
      message: evidence.length === 0
        ? '.secret_key has appropriate permissions'
        : '.secret_key has overly permissive file permissions',
      evidence: evidence.length > 0 ? evidence : undefined,
      fixable: true,
      fixDescription: 'Run: chmod 600 ~/.zeroclaw/.secret_key',
    };
  },
};
