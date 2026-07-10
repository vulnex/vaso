import { defineCheck } from '../../core/check-builder.js';
import { fixFirstConfig } from '../../remediation/config-writer.js';
import { getNestedValue } from '../../core/utils.js';

export const ic006 = defineCheck({
  id: 'IC-006',
  name: 'Sandbox Full Access Policy',
  category: 'ironclaw',
  severity: 'critical',
  description: 'Check if sandbox policy is set to full_access, granting unrestricted system access',
  supportedAgents: ['ironclaw'],

  async run(ctx, h) {
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

    return h.fromEvidence(evidence, {
      passed: 'Sandbox policy is not set to full_access',
      failed: () => 'Sandbox policy is full_access — tools have unrestricted system access',
      fixable: true,
      fixDescription: 'Set SANDBOX_POLICY=restricted or SANDBOX_POLICY=minimal in .env or sandbox.policy in config.toml',
    });
  },

  async fix(ctx) {
    return fixFirstConfig(ctx.configs, {
      checkId: 'IC-006',
      env: 'SANDBOX_POLICY',
      path: 'sandbox.policy',
      value: 'restricted',
      message: 'Set SANDBOX_POLICY=restricted',
    });
  },
});
