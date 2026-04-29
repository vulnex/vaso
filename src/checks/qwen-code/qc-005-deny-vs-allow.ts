import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

const BROAD_ALLOW = /\*|^run_shell_command$|^Shell\b/i;

export const qc005 = defineCheck({
  id: 'QC-005',
  name: 'Qwen Allow With Empty Deny',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Detect permissions.allow containing wildcards/broad patterns when permissions.deny is empty',
  supportedAgents: ['qwen-code'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      const perms = config.data.permissions as Record<string, unknown> | undefined;
      if (!perms || typeof perms !== 'object') continue;
      const allow = Array.isArray(perms.allow) ? (perms.allow as unknown[]).filter((a): a is string => typeof a === 'string') : [];
      const deny = Array.isArray(perms.deny) ? (perms.deny as unknown[]).filter((a): a is string => typeof a === 'string') : [];

      if (deny.length > 0) continue;
      const broad = allow.filter(rule => BROAD_ALLOW.test(rule));
      if (broad.length === 0) continue;

      evidence.push({
        file: config.filePath,
        snippet: `permissions.allow has ${broad.length} broad rule(s); permissions.deny is empty`,
        detail: `Broad allow rules without a deny net: ${broad.slice(0, 3).join(', ')}${broad.length > 3 ? ', …' : ''}`,
      });
    }

    return h.fromEvidence(evidence, {
      passed: 'Qwen permissions either lack broad allow rules or have a deny net',
      failed: () => 'Qwen permissions.allow includes broad patterns with empty permissions.deny',
      fixDescription: 'Add explicit deny rules (e.g., "Shell(rm)", "Write(.env)") or narrow the allow patterns',
    });
  },
});
