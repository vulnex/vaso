import type { CheckModule, ScanContext, CheckResult } from '../../core/types.js';
import { getNestedValue } from '../../core/utils.js';

export const nb003: CheckModule = {
  id: 'NB-003',
  name: 'Workspace Restriction Disabled',
  category: 'nanobot',
  severity: 'warning',
  description: 'Check if restrictToWorkspace is false, allowing file access outside the workspace',
  supportedAgents: ['nanobot'],

  async run(ctx: ScanContext): Promise<CheckResult> {
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
        // Default is false if not set
        evidence.push({
          file: config.filePath,
          detail: 'restrictToWorkspace is not configured (defaults to false) — agent can access files outside workspace',
        });
      }
    }
    return {
      id: 'NB-003', name: 'Workspace Restriction Disabled', category: 'nanobot',
      severity: 'warning', passed: evidence.length === 0,
      message: evidence.length === 0
        ? 'Workspace restriction is enabled'
        : 'Workspace restriction is disabled — agent can access files outside its workspace',
      evidence: evidence.length > 0 ? evidence : undefined,
      fixable: true, fixDescription: 'Set "restrictToWorkspace": true in config',
    };
  },
};
