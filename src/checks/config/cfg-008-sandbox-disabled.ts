import type { CheckModule, ScanContext, CheckResult, FixResult } from '../../core/types.js';
import { CODING_AGENTS } from '../../core/types.js';
import { updateConfigValue } from '../../remediation/config-writer.js';
import { getNestedValue } from '../../core/utils.js';

export const cfg008: CheckModule = {
  id: 'CFG-008',
  name: 'Sandbox Disabled',
  category: 'config',
  severity: 'critical',
  description: 'Check if code sandbox/isolation is disabled',
  excludedAgents: CODING_AGENTS,

  async run(ctx: ScanContext): Promise<CheckResult> {
    for (const config of ctx.configs) {
      const sandbox = getNestedValue(config.data, 'sandbox') ??
                      getNestedValue(config.data, 'security.sandbox') ??
                      getNestedValue(config.data, 'isolation');

      if (sandbox === false || sandbox === 'disabled' || sandbox === 'off' || sandbox === 'none') {
        return {
          id: 'CFG-008',
          name: 'Sandbox Disabled',
          category: 'config',
          severity: 'critical',
          passed: false,
          message: 'Code sandbox is explicitly disabled — skills run without isolation',
          evidence: [{ file: config.filePath, detail: `sandbox: ${String(sandbox)}` }],
          fixable: true,
          fixDescription: 'Enable sandbox mode',
        };
      }
    }

    return {
      id: 'CFG-008',
      name: 'Sandbox Disabled',
      category: 'config',
      severity: 'critical',
      passed: true,
      message: 'Sandbox is not explicitly disabled',
    };
  },

  async fix(ctx: ScanContext): Promise<FixResult> {
    for (const config of ctx.configs) {
      const keyPath = config.format === 'env' ? 'SANDBOX' : 'sandbox';
      await updateConfigValue(config, keyPath, true);
      return { checkId: 'CFG-008', applied: true, message: 'Enabled sandbox mode' };
    }
    return { checkId: 'CFG-008', applied: false, message: 'No config file found' };
  },
};
