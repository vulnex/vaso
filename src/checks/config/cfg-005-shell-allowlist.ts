import type { CheckModule, ScanContext, CheckResult } from '../../core/types.js';
import { getNestedValue } from '../../core/utils.js';

export const cfg005: CheckModule = {
  id: 'CFG-005',
  name: 'Missing Shell Allowlist',
  category: 'config',
  severity: 'warning',
  description: 'Check if a shell command allowlist (safeBins) is configured',

  async run(ctx: ScanContext): Promise<CheckResult> {
    let found = false;

    for (const config of ctx.configs) {
      const safeBins = getNestedValue(config.data, 'security.safeBins') ??
                       getNestedValue(config.data, 'safeBins') ??
                       getNestedValue(config.data, 'shell.allowlist') ??
                       config.data.SAFE_BINS;

      if (safeBins && (Array.isArray(safeBins) ? safeBins.length > 0 : true)) {
        found = true;
        break;
      }
    }

    return {
      id: 'CFG-005',
      name: 'Missing Shell Allowlist',
      category: 'config',
      severity: 'warning',
      passed: found,
      message: found
        ? 'Shell command allowlist (safeBins) is configured'
        : 'No shell command allowlist — agents can execute any command',
      fixable: true,
      fixDescription: 'Add safeBins allowlist to config',
    };
  },
};
