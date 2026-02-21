import type { CheckModule, ScanContext, CheckResult, FixResult } from '../../core/types.js';
import { updateConfigValue } from '../../remediation/config-writer.js';
import { getNestedValue } from '../../core/utils.js';

export const cfg013: CheckModule = {
  id: 'CFG-013',
  name: 'DM Policy Open',
  category: 'config',
  severity: 'warning',
  description: 'Check if direct message policy allows unrestricted messaging',

  async run(ctx: ScanContext): Promise<CheckResult> {
    for (const config of ctx.configs) {
      const dmPolicy = getNestedValue(config.data, 'dm.policy') ??
                       getNestedValue(config.data, 'messaging.dm') ??
                       getNestedValue(config.data, 'directMessage.policy');

      if (dmPolicy === 'open' || dmPolicy === 'unrestricted' || dmPolicy === 'allow_all') {
        return {
          id: 'CFG-013',
          name: 'DM Policy Open',
          category: 'config',
          severity: 'warning',
          passed: false,
          message: 'DM policy is set to open — anyone can message the agent directly',
          evidence: [{ file: config.filePath, detail: `DM policy: ${String(dmPolicy)}` }],
          fixable: true,
          fixDescription: 'Set DM policy to restricted or allowlist-only',
        };
      }
    }

    return {
      id: 'CFG-013',
      name: 'DM Policy Open',
      category: 'config',
      severity: 'warning',
      passed: true,
      message: 'DM policy is not set to open',
    };
  },

  async fix(ctx: ScanContext): Promise<FixResult> {
    for (const config of ctx.configs) {
      const keyPath = config.format === 'env' ? 'DM_POLICY' : 'dm.policy';
      await updateConfigValue(config, keyPath, 'restricted');
      return { checkId: 'CFG-013', applied: true, message: 'Set DM policy to restricted' };
    }
    return { checkId: 'CFG-013', applied: false, message: 'No config file found' };
  },
};
