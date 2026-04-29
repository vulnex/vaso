import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

const BROAD_PATTERNS = [
  /Shell\s*\(\s*\*\s*\)/i,
  /Write\s*\(\s*\*\s*\)/i,
  /Read\s*\(\s*\*\s*\)/i,
  /WebFetch\s*\(\s*\*\s*\)/i,
  /Mcp\s*\(\s*\*\s*\)/i,
];

export const cur005 = defineCheck({
  id: 'CUR-005',
  name: 'Cursor Allow With Empty Deny',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Detect permissions.allow containing wildcard patterns when permissions.deny is empty',
  supportedAgents: ['cursor-cli'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      const perms = config.data.permissions as Record<string, unknown> | undefined;
      if (!perms || typeof perms !== 'object') continue;
      const allow = Array.isArray(perms.allow) ? (perms.allow as unknown[]).filter((a): a is string => typeof a === 'string') : [];
      const deny = Array.isArray(perms.deny) ? (perms.deny as unknown[]).filter((a): a is string => typeof a === 'string') : [];

      if (deny.length > 0) continue;
      const broad = allow.filter(rule => BROAD_PATTERNS.some(p => p.test(rule)));
      if (broad.length === 0) continue;

      evidence.push({
        file: config.filePath,
        snippet: `permissions.deny is empty; allow has ${broad.length} wildcard rule(s)`,
        detail: `Wildcard allows without a deny net: ${broad.slice(0, 3).join(', ')}${broad.length > 3 ? ', …' : ''}`,
      });
    }

    return h.fromEvidence(evidence, {
      passed: 'Cursor permissions either lack wildcards or have a deny net',
      failed: () => 'Cursor permissions.allow uses wildcards but permissions.deny is empty',
      fixDescription: 'Add explicit deny rules (e.g. Shell(rm), Write(**/*.env)) or narrow the allow patterns',
    });
  },
});
