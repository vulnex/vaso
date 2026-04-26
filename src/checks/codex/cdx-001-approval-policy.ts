import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

const DANGEROUS_POLICIES = new Set(['never', 'none', 'auto']);

export const cdx001 = defineCheck({
  id: 'CDX-001',
  name: 'Codex Approval Policy Disabled',
  category: 'coding-agent',
  severity: 'critical',
  description: 'Detect when Codex approval_policy is set to a value that skips user confirmation',
  supportedAgents: ['codex'],

  async run(ctx, h) {
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

    return h.fromEvidence(evidence, {
      passed: 'Codex approval policy requires user confirmation',
      failed: () => 'Codex approval policy bypasses user confirmation',
      fixDescription: 'Set approval_policy to "untrusted", "on-failure", or "on-request" in ~/.codex/config.toml',
    });
  },
});
