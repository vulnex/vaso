import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { isLegacy, isLegacyUnused, legacySetting, lineOf, str } from './layout.js';

/*
 * 0.x only: SANDBOX_EXTRA_DOMAINS (comma-separated env) /
 * [sandbox].extra_allowed_domains (config.toml overlay array) extends the
 * sandbox egress-proxy allowlist. Wildcards reopen exfiltration paths from
 * sandboxed tool runs. (The old `sandbox.extra_domains` key never existed.)
 */

export const ic011 = defineCheck({
  id: 'IC-011',
  name: 'Broad Sandbox Domain Allowlist (0.x)',
  category: 'ironclaw',
  severity: 'warning',
  description: 'Check if IronClaw 0.x SANDBOX_EXTRA_DOMAINS / [sandbox].extra_allowed_domains contains wildcard patterns that weaken sandbox network isolation',
  supportedAgents: ['ironclaw'],

  async run(ctx, h) {
    if (!isLegacy(ctx)) return h.passed('Not applicable to IronClaw 1.x');
    if (isLegacyUnused(ctx)) return h.passed('0.x configuration is not used by the installed IronClaw 1.x binary');

    const evidence: Evidence[] = [];
    for (const s of legacySetting(ctx, 'SANDBOX_EXTRA_DOMAINS', 'sandbox.extra_allowed_domains')) {
      const list = Array.isArray(s.value)
        ? s.value.map(v => str(v) ?? '')
        : (str(s.value) ?? '').split(',').map(d => d.trim());
      const wildcards = list.filter(d => d.includes('*'));
      if (wildcards.length === 0) continue;
      const line = lineOf(s.config, s.config.format === 'env' ? s.key : 'extra_allowed_domains');
      evidence.push({
        file: s.file,
        ...(line ? { line } : {}),
        detail: `${s.key} contains wildcard patterns: ${wildcards.join(', ')} — weakens sandbox network isolation`,
      });
    }

    return h.fromEvidence(evidence, {
      passed: 'No wildcard patterns in the sandbox domain allowlist',
      failed: () => 'Sandbox domain allowlist contains wildcard patterns — network isolation is weakened',
      fixDescription: 'Replace wildcard entries in SANDBOX_EXTRA_DOMAINS with specific fully-qualified domain names',
    });
  },
});
