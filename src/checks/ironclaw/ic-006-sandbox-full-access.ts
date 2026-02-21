import type { CheckModule, ScanContext, CheckResult } from '../../core/types.js';
import { getNestedValue } from '../../core/utils.js';

export const ic006: CheckModule = {
  id: 'IC-006',
  name: 'Sandbox Full Access Policy',
  category: 'ironclaw',
  severity: 'critical',
  description: 'Check if sandbox policy is set to full_access, granting unrestricted system access',
  supportedAgents: ['ironclaw'],

  async run(ctx: ScanContext): Promise<CheckResult> {
    const evidence = [];

    for (const config of ctx.configs) {
      const policy =
        (config.data.SANDBOX_POLICY as string | undefined) ??
        (getNestedValue(config.data, 'sandbox.policy') as string | undefined);

      if (typeof policy === 'string' && policy.toLowerCase() === 'full_access') {
        evidence.push({
          file: config.filePath,
          detail: `SANDBOX_POLICY=${policy} — tools have unrestricted system access`,
        });
      }
    }

    return {
      id: 'IC-006',
      name: 'Sandbox Full Access Policy',
      category: 'ironclaw',
      severity: 'critical',
      passed: evidence.length === 0,
      message: evidence.length === 0
        ? 'Sandbox policy is not set to full_access'
        : 'Sandbox policy is full_access — tools have unrestricted system access',
      evidence: evidence.length > 0 ? evidence : undefined,
      fixable: true,
      fixDescription: 'Set SANDBOX_POLICY=restricted or SANDBOX_POLICY=minimal in .env or sandbox.policy in config.toml',
    };
  },
};
