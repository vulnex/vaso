import type { CheckModule, ScanContext, CheckResult, Evidence } from '../../core/types.js';
import { getNestedValue } from '../../core/utils.js';

export const cdx005: CheckModule = {
  id: 'CDX-005',
  name: 'Codex Shell Env Inherits All',
  category: 'coding-agent',
  severity: 'critical',
  description: 'Detect when shell_environment_policy.inherit = "all" leaks every env var (including secrets) to subprocess shells',
  supportedAgents: ['codex'],

  async run(ctx: ScanContext): Promise<CheckResult> {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      const inherit =
        getNestedValue(config.data, 'shell_environment_policy.inherit') ??
        getNestedValue(config.data, 'shellEnvironmentPolicy.inherit');

      if (typeof inherit === 'string' && inherit.toLowerCase() === 'all') {
        evidence.push({
          file: config.filePath,
          detail: 'shell_environment_policy.inherit = "all" — every parent env var (incl. AWS_*, GITHUB_TOKEN, ANTHROPIC_API_KEY) is exposed to tool subprocesses and MCP servers',
        });
      }
    }

    return {
      id: 'CDX-005',
      name: 'Codex Shell Env Inherits All',
      category: 'coding-agent',
      severity: 'critical',
      passed: evidence.length === 0,
      message: evidence.length === 0
        ? 'Codex shell environment policy is restricted'
        : 'Codex inherits the entire process environment into tool subprocesses',
      evidence: evidence.length > 0 ? evidence : undefined,
      fixable: false,
      fixDescription: 'Set [shell_environment_policy] inherit = "core" (or "none") and use include_only/set for the specific vars tools need',
    };
  },
};
