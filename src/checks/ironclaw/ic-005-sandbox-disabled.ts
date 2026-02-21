import type { CheckModule, ScanContext, CheckResult } from '../../core/types.js';
import { getNestedValue } from '../../core/utils.js';

export const ic005: CheckModule = {
  id: 'IC-005',
  name: 'Sandbox Disabled',
  category: 'ironclaw',
  severity: 'critical',
  description: 'Check if sandbox isolation is explicitly disabled',
  supportedAgents: ['ironclaw'],

  async run(ctx: ScanContext): Promise<CheckResult> {
    const evidence = [];

    for (const config of ctx.configs) {
      const sandboxEnabled =
        (config.data.SANDBOX_ENABLED as string | undefined) ??
        (getNestedValue(config.data, 'sandbox.enabled') as string | boolean | undefined);

      if (sandboxEnabled === false || sandboxEnabled === 'false') {
        evidence.push({
          file: config.filePath,
          detail: 'SANDBOX_ENABLED=false — all tools execute without isolation',
        });
      }
    }

    return {
      id: 'IC-005',
      name: 'Sandbox Disabled',
      category: 'ironclaw',
      severity: 'critical',
      passed: evidence.length === 0,
      message: evidence.length === 0
        ? 'Sandbox is not explicitly disabled'
        : 'Sandbox is disabled — tools execute without isolation',
      evidence: evidence.length > 0 ? evidence : undefined,
      fixable: true,
      fixDescription: 'Set SANDBOX_ENABLED=true in .env or sandbox.enabled=true in config.toml',
    };
  },
};
