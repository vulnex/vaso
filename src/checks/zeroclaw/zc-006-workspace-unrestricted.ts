import type { CheckModule, ScanContext, CheckResult, FixResult } from '../../core/types.js';
import { getNestedValue } from '../../core/utils.js';
import { updateTomlFile } from '../../remediation/config-writer.js';

export const zc006: CheckModule = {
  id: 'ZC-006',
  name: 'Workspace Unrestricted',
  category: 'zeroclaw',
  severity: 'warning',
  description: 'Detect workspace_only=false which allows filesystem access beyond workspace',
  supportedAgents: ['zeroclaw'],

  async run(ctx: ScanContext): Promise<CheckResult> {
    const evidence = [];

    for (const config of ctx.configs) {
      const workspaceOnly =
        getNestedValue(config.data, 'workspace_only') ??
        config.data.WORKSPACE_ONLY;

      if (workspaceOnly === false || workspaceOnly === 'false') {
        evidence.push({
          file: config.filePath,
          detail: 'workspace_only=false — agent can access files outside the workspace directory',
        });
      }
    }

    return {
      id: 'ZC-006',
      name: 'Workspace Unrestricted',
      category: 'zeroclaw',
      severity: 'warning',
      passed: evidence.length === 0,
      message: evidence.length === 0
        ? 'Filesystem access is restricted to workspace'
        : 'Filesystem access is unrestricted — agent can access files outside workspace',
      evidence: evidence.length > 0 ? evidence : undefined,
      fixable: true,
      fixDescription: 'Set workspace_only=true to restrict filesystem access to the workspace directory',
    };
  },

  async fix(ctx: ScanContext): Promise<FixResult> {
    for (const config of ctx.configs) {
      if (config.format === 'toml') {
        await updateTomlFile(config.filePath, 'workspace_only', true);
        return { checkId: 'ZC-006', applied: true, message: 'Set workspace_only=true' };
      }
    }
    return { checkId: 'ZC-006', applied: false, message: 'No TOML config file found' };
  },
};
