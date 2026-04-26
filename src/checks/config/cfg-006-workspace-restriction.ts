import type { CheckModule, ScanContext, CheckResult } from '../../core/types.js';
import { CODING_AGENTS } from '../../core/types.js';
import { getNestedValue } from '../../core/utils.js';

export const cfg006: CheckModule = {
  id: 'CFG-006',
  name: 'No Workspace Restriction',
  category: 'config',
  severity: 'warning',
  description: 'Check if filesystem access is restricted to a workspace directory',
  excludedAgents: CODING_AGENTS,

  async run(ctx: ScanContext): Promise<CheckResult> {
    let found = false;

    for (const config of ctx.configs) {
      const workspace = getNestedValue(config.data, 'workspace') ??
                        getNestedValue(config.data, 'security.workspace') ??
                        getNestedValue(config.data, 'fs.root') ??
                        getNestedValue(config.data, 'filesystem.restricted') ??
                        config.data.WORKSPACE_DIR;

      if (workspace) {
        found = true;
        break;
      }
    }

    return {
      id: 'CFG-006',
      name: 'No Workspace Restriction',
      category: 'config',
      severity: 'warning',
      passed: found,
      message: found
        ? 'Filesystem access is restricted to a workspace directory'
        : 'No workspace restriction — agent has unrestricted filesystem access',
    };
  },
};
