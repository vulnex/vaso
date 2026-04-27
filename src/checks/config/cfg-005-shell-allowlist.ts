import { defineCheck } from '../../core/check-builder.js';
import { CODING_AGENTS } from '../../core/types.js';
import { updateConfigValue } from '../../remediation/config-writer.js';
import { getNestedValue } from '../../core/utils.js';

export const cfg005 = defineCheck({
  id: 'CFG-005',
  name: 'Missing Shell Allowlist',
  category: 'config',
  severity: 'warning',
  description: 'Check if a shell command allowlist (safeBins) is configured',
  excludedAgents: CODING_AGENTS,

  async run(ctx, h) {
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

    return h.result({
      passed: found,
      message: found
        ? 'Shell command allowlist (safeBins) is configured'
        : 'No shell command allowlist — agents can execute any command',
      fixable: true,
      fixDescription: 'Add safeBins allowlist to config',
    });
  },

  async fix(ctx) {
    const safeBins = ['ls', 'cat', 'grep', 'head', 'tail', 'wc', 'echo', 'date'];
    for (const config of ctx.configs) {
      const keyPath = config.format === 'env' ? 'SAFE_BINS' : 'security.safeBins';
      const value = config.format === 'env' ? safeBins.join(',') : safeBins;
      await updateConfigValue(config, keyPath, value);
      return { checkId: 'CFG-005', applied: true, message: 'Added safeBins allowlist with safe defaults' };
    }
    return { checkId: 'CFG-005', applied: false, message: 'No config file found' };
  },
});
