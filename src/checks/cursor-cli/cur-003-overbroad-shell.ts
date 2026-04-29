import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

const OVERBROAD_SHELL = [
  /^Shell$/i,
  /^Shell\s*\(\s*\*\s*\)$/i,
  /^Shell\s*\(\s*(bash|sh|zsh|fish|cmd|powershell|pwsh)\s*\)$/i,
  /^Shell\s*\(\s*(rm|sudo|curl|wget|nc|ncat|eval|exec)\s*\)$/i,
];

export const cur003 = defineCheck({
  id: 'CUR-003',
  name: 'Cursor Overbroad Shell Allow',
  category: 'coding-agent',
  severity: 'critical',
  description: 'Detect permissions.allow entries that grant unbounded shell access',
  supportedAgents: ['cursor-cli'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      const perms = config.data.permissions as Record<string, unknown> | undefined;
      if (!perms || typeof perms !== 'object') continue;
      const allow = Array.isArray(perms.allow) ? (perms.allow as unknown[]).filter((a): a is string => typeof a === 'string') : [];
      const deny = Array.isArray(perms.deny) ? (perms.deny as unknown[]).filter((a): a is string => typeof a === 'string') : [];
      const denySet = new Set(deny.map(d => d.toLowerCase()));

      for (const rule of allow) {
        if (denySet.has(rule.toLowerCase())) continue; // deny wins
        if (!OVERBROAD_SHELL.some(p => p.test(rule))) continue;
        evidence.push({
          file: config.filePath,
          snippet: `permissions.allow: "${rule}"`,
          detail: 'Auto-approves arbitrary shell commands — covers far more than intended',
        });
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'Cursor permissions.allow has no overbroad shell entries',
      failed: (n) => `Found ${n} overbroad Shell allow rule(s) in Cursor config`,
      fixDescription: 'Replace catch-alls with specific commands (e.g. Shell(git), Shell(npm)) and add deny rules for risky shells',
    });
  },
});
