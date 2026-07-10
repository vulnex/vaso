import { defineCheck } from '../../core/check-builder.js';
import { fixFirstConfig } from '../../remediation/config-writer.js';
import { getNestedValue } from '../../core/utils.js';

export const ic008 = defineCheck({
  id: 'IC-008',
  name: 'Local Tools Bypass',
  category: 'ironclaw',
  severity: 'warning',
  description: 'Check if ALLOW_LOCAL_TOOLS is enabled, allowing tools to execute outside the sandbox',
  supportedAgents: ['ironclaw'],

  async run(ctx, h) {
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

    return h.fromEvidence(evidence, {
      passed: 'Local tools bypass is not enabled',
      failed: () => 'Local tools bypass is enabled — tools can execute outside the sandbox',
      fixable: true,
      fixDescription: 'Set ALLOW_LOCAL_TOOLS=false in .env or tools.allow_local=false in config.toml',
    });
  },

  async fix(ctx) {
    return fixFirstConfig(ctx.configs, {
      checkId: 'IC-008',
      env: 'ALLOW_LOCAL_TOOLS',
      path: 'tools.allow_local',
      value: false,
      message: 'Set ALLOW_LOCAL_TOOLS=false',
    });
  },
});
