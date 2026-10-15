import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { codexProfileName } from '../../adapters/codex.js';

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
      // Profile files only apply under `codex -p <name>` — CDX-008's finding
      if (codexProfileName(config.filePath)) continue;
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
      // "untrusted" and "on-failure" are deprecated upstream; "on-request" (or a
      // granular policy) is the supported prompting mode
      fixDescription: 'Set approval_policy to "on-request" (or a { granular = { … } } policy) in ~/.codex/config.toml',
    });
  },
});
