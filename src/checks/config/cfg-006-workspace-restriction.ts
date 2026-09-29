import { defineCheck } from '../../core/check-builder.js';
import { CODING_AGENTS } from '../../core/types.js';
import { NATIVE_POLICY_FRAMEWORKS } from './native-policy-frameworks.js';
import { getNestedValue } from '../../core/utils.js';

export const cfg006 = defineCheck({
  id: 'CFG-006',
  name: 'No Workspace Restriction',
  category: 'config',
  severity: 'warning',
  description: 'Check if filesystem access is restricted to a workspace directory',
  // Atomic Agent confines reads via agent.readScope (AT-002), not a workspace key.
  // The other frameworks listed scope the filesystem in their own schemas (framework checks).
  excludedAgents: [...CODING_AGENTS, ...NATIVE_POLICY_FRAMEWORKS],

  async run(ctx, h) {
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

    return h.result({
      passed: found,
      message: found
        ? 'Filesystem access is restricted to a workspace directory'
        : 'No workspace restriction — agent has unrestricted filesystem access',
    });
  },
});
