import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { getNestedValue } from '../../core/utils.js';

export const cdx005 = defineCheck({
  id: 'CDX-005',
  name: 'Codex Shell Env Inherits All',
  category: 'coding-agent',
  severity: 'critical',
  description: 'Detect when shell_environment_policy.inherit = "all" leaks every env var (including secrets) to subprocess shells',
  supportedAgents: ['codex'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      const inherit =
        getNestedValue(config.data, 'shell_environment_policy.inherit') ??
        getNestedValue(config.data, 'shellEnvironmentPolicy.inherit');

      if (typeof inherit === 'string' && inherit.toLowerCase() === 'all') {
        const policy = (getNestedValue(config.data, 'shell_environment_policy')
          ?? getNestedValue(config.data, 'shellEnvironmentPolicy')) as Record<string, unknown> | undefined;
        // ignore_default_excludes = false drops every name containing KEY,
        // SECRET or TOKEN before the filters apply; include_only keeps just
        // the listed names (learn.chatgpt.com/docs/config-file/config-advanced)
        const defaultExcludes = policy?.ignore_default_excludes === false;
        const includeOnly = Array.isArray(policy?.include_only)
          && policy.include_only.length > 0
          && policy.include_only.every(p => typeof p === 'string' && p !== '*');
        if (defaultExcludes || includeOnly) {
          evidence.push({
            file: config.filePath,
            mitigated: true,
            detail: defaultExcludes
              ? 'shell_environment_policy.inherit = "all", but ignore_default_excludes = false removes every variable named *KEY*, *SECRET* or *TOKEN* first'
              : 'shell_environment_policy.inherit = "all", narrowed by an include_only allowlist',
          });
          continue;
        }
        evidence.push({
          file: config.filePath,
          detail: 'shell_environment_policy.inherit = "all" — every parent env var (incl. AWS_*, GITHUB_TOKEN, ANTHROPIC_API_KEY) is exposed to tool subprocesses and MCP servers',
        });
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'Codex shell environment policy is restricted',
      failed: () => 'Codex inherits the entire process environment into tool subprocesses',
      fixDescription: 'Set [shell_environment_policy] inherit = "core" (or "none") and use include_only/set for the specific vars tools need',
    });
  },
});
