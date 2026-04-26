import type { CheckModule, ScanContext, CheckResult, Evidence } from '../../core/types.js';

const DANGEROUS_POLICIES = new Set(['never', 'none', 'auto']);

export const cdx001: CheckModule = {
  id: 'CDX-001',
  name: 'Codex Approval Policy Disabled',
  category: 'coding-agent',
  severity: 'critical',
  description: 'Detect when Codex approval_policy is set to a value that skips user confirmation',
  supportedAgents: ['codex'],

  async run(ctx: ScanContext): Promise<CheckResult> {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      const policy = config.data.approval_policy ?? config.data.approvalPolicy;
      if (typeof policy === 'string' && DANGEROUS_POLICIES.has(policy.toLowerCase())) {
        evidence.push({
          file: config.filePath,
          detail: `approval_policy = "${policy}" — Codex will execute commands without user approval`,
        });
      }
    }

    return {
      id: 'CDX-001',
      name: 'Codex Approval Policy Disabled',
      category: 'coding-agent',
      severity: 'critical',
      passed: evidence.length === 0,
      message: evidence.length === 0
        ? 'Codex approval policy requires user confirmation'
        : 'Codex approval policy bypasses user confirmation',
      evidence: evidence.length > 0 ? evidence : undefined,
      fixable: false,
      fixDescription: 'Set approval_policy to "untrusted", "on-failure", or "on-request" in ~/.codex/config.toml',
    };
  },
};
