import { defineCheck } from '../../core/check-builder.js';
import { getNestedValue } from '../../core/utils.js';

export const ic011 = defineCheck({
  id: 'IC-011',
  name: 'Broad Sandbox Domain Allowlist',
  category: 'ironclaw',
  severity: 'warning',
  description: 'Check if SANDBOX_EXTRA_DOMAINS contains wildcard patterns that weaken network isolation',
  supportedAgents: ['ironclaw'],

  async run(ctx, h) {
    const evidence = [];

    for (const config of ctx.configs) {
      const extraDomains =
        (config.data.SANDBOX_EXTRA_DOMAINS as string | undefined) ??
        (getNestedValue(config.data, 'sandbox.extra_domains') as string | string[] | undefined) ??
        (getNestedValue(config.data, 'sandbox.extraDomains') as string | string[] | undefined);

      if (!extraDomains) continue;

      const domainList = Array.isArray(extraDomains)
        ? extraDomains
        : extraDomains.split(',').map(d => d.trim());

      const wildcards = domainList.filter(d => {
        if (d === '*') return true;
        if (d.startsWith('*.')) return true;
        if (d.includes('*')) return true;
        return false;
      });

      if (wildcards.length > 0) {
        evidence.push({
          file: config.filePath,
          detail: `SANDBOX_EXTRA_DOMAINS contains wildcard patterns: ${wildcards.join(', ')} — weakens network isolation`,
        });
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'No wildcard patterns in sandbox domain allowlist',
      failed: () => 'Sandbox domain allowlist contains wildcard patterns — network isolation is weakened',
      fixDescription: 'Replace wildcard domain patterns with specific fully-qualified domain names in SANDBOX_EXTRA_DOMAINS',
    });
  },
});
