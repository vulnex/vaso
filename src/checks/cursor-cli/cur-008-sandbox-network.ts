import { basename } from 'node:path';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

const UNRESTRICTED_VALUES = new Set(['unrestricted', 'allowed', 'all', 'true']);

export const cur008 = defineCheck({
  id: 'CUR-008',
  name: 'Cursor Sandbox Network Unrestricted',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Detect sandbox.networkAccess (cli-config.json) or sandbox.json networkPolicy set to allow any host — sandboxed tools can reach arbitrary hosts',
  supportedAgents: ['cursor-cli'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      // sandbox.json networkPolicy: default "deny" unless set to "allow";
      // a "*" allow entry opens every domain (cursor.com/docs/reference/sandbox)
      if (basename(config.filePath) === 'sandbox.json') {
        const policy = config.data.networkPolicy as Record<string, unknown> | undefined;
        if (!policy || typeof policy !== 'object') continue;
        if (typeof policy.default === 'string' && policy.default.toLowerCase() === 'allow') {
          evidence.push({
            file: config.filePath,
            snippet: 'networkPolicy.default = "allow"',
            detail: 'Sandboxed commands may reach any host not explicitly denied — exfiltration paths stay open with the sandbox on',
          });
        } else if (Array.isArray(policy.allow) && policy.allow.some(a => typeof a === 'string' && /^\s*\*\s*$/.test(a))) {
          evidence.push({
            file: config.filePath,
            snippet: 'networkPolicy.allow contains "*"',
            detail: 'A "*" allow entry lets sandboxed commands reach any host',
          });
        }
        continue;
      }
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
      fixDescription: 'Set sandbox.networkAccess to "user_config_with_defaults" (cli-config.json) and keep sandbox.json networkPolicy.default "deny" with named domains in networkPolicy.allow',
    });
  },
});
