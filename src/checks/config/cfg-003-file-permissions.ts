import { stat } from 'node:fs/promises';
import type { CheckModule, ScanContext, CheckResult, Evidence } from '../../core/types.js';

export const cfg003: CheckModule = {
  id: 'CFG-003',
  name: 'File Permissions',
  category: 'config',
  severity: 'warning',
  description: 'Check that config files have restrictive permissions (600 or tighter)',
  supportedPlatforms: ['darwin', 'linux'],

  async run(ctx: ScanContext): Promise<CheckResult> {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      try {
        const stats = await stat(config.filePath);
        const mode = stats.mode & 0o777;
        // Warn if group or other has any access
        if (mode & 0o077) {
          evidence.push({
            file: config.filePath,
            detail: `Permissions: ${mode.toString(8)} (should be 600 or tighter)`,
          });
        }
      } catch {
        // File may not exist
      }
    }

    return {
      id: 'CFG-003',
      name: 'File Permissions',
      category: 'config',
      severity: 'warning',
      passed: evidence.length === 0,
      message: evidence.length === 0
        ? 'All config files have restrictive permissions'
        : `${evidence.length} config file(s) have overly permissive permissions`,
      evidence: evidence.length > 0 ? evidence : undefined,
      fixable: true,
      fixDescription: 'Set permissions to 600 (chmod 600)',
    };
  },
};
