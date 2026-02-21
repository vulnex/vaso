import type { CheckModule, ScanContext, CheckResult } from '../../core/types.js';
import { getNestedValue } from '../../core/utils.js';

export const ic008: CheckModule = {
  id: 'IC-008',
  name: 'Local Tools Bypass',
  category: 'ironclaw',
  severity: 'warning',
  description: 'Check if ALLOW_LOCAL_TOOLS is enabled, allowing tools to execute outside the sandbox',
  supportedAgents: ['ironclaw'],

  async run(ctx: ScanContext): Promise<CheckResult> {
    const evidence = [];

    for (const config of ctx.configs) {
      const allowLocal =
        (config.data.ALLOW_LOCAL_TOOLS as string | undefined) ??
        (getNestedValue(config.data, 'tools.allow_local') as string | boolean | undefined) ??
        (getNestedValue(config.data, 'tools.allowLocal') as string | boolean | undefined);

      if (allowLocal === true || allowLocal === 'true') {
        evidence.push({
          file: config.filePath,
          detail: 'ALLOW_LOCAL_TOOLS=true — tools can execute outside the sandbox boundary',
        });
      }
    }

    return {
      id: 'IC-008',
      name: 'Local Tools Bypass',
      category: 'ironclaw',
      severity: 'warning',
      passed: evidence.length === 0,
      message: evidence.length === 0
        ? 'Local tools bypass is not enabled'
        : 'Local tools bypass is enabled — tools can execute outside the sandbox',
      evidence: evidence.length > 0 ? evidence : undefined,
      fixable: true,
      fixDescription: 'Set ALLOW_LOCAL_TOOLS=false in .env or tools.allow_local=false in config.toml',
    };
  },
};
