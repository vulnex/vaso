import { defineCheck } from '../../core/check-builder.js';
import { getNestedValue } from '../../core/utils.js';
import { fixFirstConfig } from '../../remediation/config-writer.js';

export const zc006 = defineCheck({
  id: 'ZC-006',
  name: 'Workspace Unrestricted',
  category: 'zeroclaw',
  severity: 'warning',
  description: 'Detect workspace_only=false which allows filesystem access beyond workspace',
  supportedAgents: ['zeroclaw'],

  async run(ctx, h) {
    const evidence = [];

    for (const config of ctx.configs) {
      const workspaceOnly =
        getNestedValue(config.data, 'workspace.workspace_only') ??
        getNestedValue(config.data, 'workspace_only') ??
        config.data.WORKSPACE_ONLY;

      if (workspaceOnly === false || workspaceOnly === 'false') {
        evidence.push({
          file: config.filePath,
          detail: 'workspace_only=false — agent can access files outside the workspace directory',
        });
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'Filesystem access is restricted to workspace',
      failed: () => 'Filesystem access is unrestricted — agent can access files outside workspace',
      fixable: true,
      fixDescription: 'Set workspace_only=true to restrict filesystem access to the workspace directory',
    });
  },

  async fix(ctx) {
    return fixFirstConfig(ctx.configs, {
      checkId: 'ZC-006',
      path: 'workspace_only',
      value: true,
      message: 'Set workspace_only=true',
      noConfigMessage: 'No TOML config file found',
    });
  },
});
