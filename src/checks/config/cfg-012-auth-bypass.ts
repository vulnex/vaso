import type { CheckModule, ScanContext, CheckResult, Evidence } from '../../core/types.js';
import { getNestedValue } from '../../core/utils.js';

export const cfg012: CheckModule = {
  id: 'CFG-012',
  name: 'Auth Bypass Enabled',
  category: 'config',
  severity: 'critical',
  description: 'Check if authentication bypass is enabled in configuration',

  async run(ctx: ScanContext): Promise<CheckResult> {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      const authBypass = getNestedValue(config.data, 'auth.bypass') ??
                         getNestedValue(config.data, 'gateway.auth.bypass') ??
                         getNestedValue(config.data, 'security.authBypass') ??
                         getNestedValue(config.data, 'noAuth');

      if (authBypass === true || authBypass === 'true' || authBypass === 1) {
        evidence.push({
          file: config.filePath,
          detail: 'Authentication bypass is enabled',
        });
      }

      const authMode = getNestedValue(config.data, 'gateway.auth.mode') ??
                       getNestedValue(config.data, 'auth.mode');

      if (authMode === 'none' || authMode === 'disabled') {
        evidence.push({
          file: config.filePath,
          detail: `Auth mode set to "${authMode}"`,
        });
      }
    }

    return {
      id: 'CFG-012',
      name: 'Auth Bypass Enabled',
      category: 'config',
      severity: 'critical',
      passed: evidence.length === 0,
      message: evidence.length === 0
        ? 'Authentication bypass is not enabled'
        : 'Authentication bypass is enabled — anyone can access the agent',
      evidence: evidence.length > 0 ? evidence : undefined,
      fixable: true,
      fixDescription: 'Disable auth bypass and set proper auth mode',
    };
  },
};
