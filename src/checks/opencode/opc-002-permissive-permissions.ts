import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

const HIGH_RISK_KEYS = new Set(['bash', 'edit', 'task', 'webfetch', 'external_directory']);

function actionFor(rule: unknown): string | undefined {
  if (typeof rule === 'string') return rule;
  if (rule && typeof rule === 'object') {
    const obj = rule as Record<string, unknown>;
    const star = obj['*'];
    if (typeof star === 'string') return star;
    // If the object has any "allow" entry, surface it — globally allowing
    // anything for a high-risk tool is a finding regardless of the glob.
    for (const v of Object.values(obj)) {
      if (typeof v === 'string' && v.toLowerCase() === 'allow') return 'allow';
    }
  }
  return undefined;
}

export const opc002 = defineCheck({
  id: 'OPC-002',
  name: 'OpenCode Permission Auto-Allow',
  category: 'coding-agent',
  severity: 'critical',
  description: 'Detect when OpenCode permissions auto-allow shell, edit, or other high-risk tools',
  supportedAgents: ['opencode'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      // Top-level shorthand: permission: "allow"
      const perm = config.data.permission;
      if (typeof perm === 'string' && perm.toLowerCase() === 'allow') {
        evidence.push({
          file: config.filePath,
          detail: 'permission = "allow" — every tool runs without user confirmation',
        });
        continue;
      }
      if (perm && typeof perm === 'object') {
        for (const key of HIGH_RISK_KEYS) {
          const action = actionFor((perm as Record<string, unknown>)[key]);
          if (action && action.toLowerCase() === 'allow') {
            evidence.push({
              file: config.filePath,
              snippet: `permission.${key} = "allow"`,
              detail: `${key} runs without user confirmation`,
            });
          }
        }
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'OpenCode permissions require user confirmation for high-risk tools',
      failed: (n) => `Found ${n} high-risk OpenCode permission(s) set to "allow"`,
      fixDescription: 'Set permission.bash and permission.edit to "ask" (or "deny") in opencode.json',
    });
  },
});
