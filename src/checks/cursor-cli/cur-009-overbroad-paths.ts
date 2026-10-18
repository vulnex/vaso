import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { overbroadPathRule } from './permission-rules.js';

const OVERBROAD_WEB_RULES = [
  /^WebFetch\s*\(\s*\*\s*\)$/i,
  /^Mcp\s*\(\s*\*\s*(:\s*\*\s*)?\)$/i,
];

export const cur009 = defineCheck({
  id: 'CUR-009',
  name: 'Cursor Overbroad Path/Web Allow',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Detect permissions.allow entries granting unbounded Write/Read/WebFetch/Mcp access',
  supportedAgents: ['cursor-cli'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    const home = ctx.fs.homedir();

    for (const config of ctx.configs) {
      const perms = config.data.permissions as Record<string, unknown> | undefined;
      if (!perms || typeof perms !== 'object') continue;
      const allow = Array.isArray(perms.allow) ? (perms.allow as unknown[]).filter((a): a is string => typeof a === 'string') : [];

      for (const rule of allow) {
        const pathReason = overbroadPathRule(rule, home);
        if (!pathReason && !OVERBROAD_WEB_RULES.some(p => p.test(rule))) continue;
        evidence.push({
          file: config.filePath,
          snippet: `permissions.allow: "${rule}"`,
          detail: pathReason
            ? `Path rule ${pathReason} — grants far more access than typically intended`
            : 'Wildcard path/web rule grants far more access than typically intended',
        });
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'Cursor allow rules have no unbounded path or web wildcards',
      failed: (n) => `Found ${n} overbroad path/web allow rule(s) in Cursor config`,
      fixDescription: 'Narrow rules to specific paths/domains (e.g. Write(src/**), WebFetch(*.example.com))',
    });
  },
});
