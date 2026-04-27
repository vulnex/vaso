import { defineCheck } from '../../core/check-builder.js';
import { updateEnvFile, updateTomlFile } from '../../remediation/config-writer.js';
import { getNestedValue } from '../../core/utils.js';

export const ic005 = defineCheck({
  id: 'IC-005',
  name: 'Sandbox Disabled',
  category: 'ironclaw',
  severity: 'critical',
  description: 'Check if sandbox isolation is explicitly disabled',
  supportedAgents: ['ironclaw'],

  async run(ctx, h) {
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

    return h.fromEvidence(evidence, {
      passed: 'Sandbox is not explicitly disabled',
      failed: () => 'Sandbox is disabled — tools execute without isolation',
      fixable: true,
      fixDescription: 'Set SANDBOX_ENABLED=true in .env or sandbox.enabled=true in config.toml',
    });
  },

  async fix(ctx) {
    for (const config of ctx.configs) {
      if (config.format === 'env') {
        await updateEnvFile(config.filePath, 'SANDBOX_ENABLED', 'true');
        return { checkId: 'IC-005', applied: true, message: 'Set SANDBOX_ENABLED=true' };
      }
      if (config.format === 'toml') {
        await updateTomlFile(config.filePath, 'sandbox.enabled', true);
        return { checkId: 'IC-005', applied: true, message: 'Set SANDBOX_ENABLED=true' };
      }
    }
    return { checkId: 'IC-005', applied: false, message: 'No compatible config file found' };
  },
});
