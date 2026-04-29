import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

const UNRESTRICTED_VALUES = new Set(['unrestricted', 'allowed', 'all', 'true']);

export const cur008 = defineCheck({
  id: 'CUR-008',
  name: 'Cursor Sandbox Network Unrestricted',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Detect sandbox.networkAccess set to an unrestricted value — sandboxed tools can reach arbitrary hosts',
  supportedAgents: ['cursor-cli'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      const sandbox = config.data.sandbox as Record<string, unknown> | undefined;
      if (!sandbox || typeof sandbox !== 'object') continue;
      const access = sandbox.networkAccess;
      if (typeof access === 'string' && UNRESTRICTED_VALUES.has(access.toLowerCase())) {
        evidence.push({
          file: config.filePath,
          snippet: `sandbox.networkAccess = "${access}"`,
          detail: 'Sandboxed tools have unrestricted network access — exfiltration paths exist even when sandbox is on',
        });
      } else if (access === true) {
        evidence.push({
          file: config.filePath,
          snippet: 'sandbox.networkAccess = true',
          detail: 'Sandboxed tools have unrestricted network access',
        });
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'Cursor sandbox network access is restricted (or unset)',
      failed: () => 'Cursor sandbox network access is unrestricted',
      fixDescription: 'Set sandbox.networkAccess to "user_config_with_defaults" or a stricter value in ~/.cursor/cli-config.json',
    });
  },
});
