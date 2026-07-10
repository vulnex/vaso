import { defineCheck } from '../../core/check-builder.js';
import { getNestedValue } from '../../core/utils.js';
import { fixFirstConfig } from '../../remediation/config-writer.js';

export const nb003 = defineCheck({
  id: 'NB-003',
  name: 'Workspace Restriction Disabled',
  category: 'nanobot',
  severity: 'warning',
  description: 'Check if restrictToWorkspace is false, allowing file access outside the workspace',
  supportedAgents: ['nanobot'],

  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const restrict = getNestedValue(config.data, 'restrictToWorkspace')
        ?? getNestedValue(config.data, 'security.restrictToWorkspace');

      if (restrict === false) {
        evidence.push({
          file: config.filePath,
          detail: 'restrictToWorkspace is explicitly set to false — agent can access files outside workspace',
        });
      } else if (restrict === undefined) {
        evidence.push({
          file: config.filePath,
          detail: 'restrictToWorkspace is not configured (defaults to false) — agent can access files outside workspace',
        });
      }
    }
    return h.fromEvidence(evidence, {
      passed: 'Workspace restriction is enabled',
      failed: () => 'Workspace restriction is disabled — agent can access files outside its workspace',
      fixable: true,
      fixDescription: 'Set "restrictToWorkspace": true in config',
    });
  },

  async fix(ctx) {
    return fixFirstConfig(ctx.configs, {
      checkId: 'NB-003',
      path: 'restrictToWorkspace',
      value: true,
      message: 'Set restrictToWorkspace=true',
      noConfigMessage: 'No JSON config file found',
    });
  },
});
