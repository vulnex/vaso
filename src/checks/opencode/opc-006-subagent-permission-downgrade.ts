import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

const RISK_LEVEL: Record<string, number> = { deny: 0, ask: 1, allow: 2 };
const TRACKED_KEYS = ['bash', 'edit', 'webfetch', 'task'];

function actionLevel(rule: unknown): number | undefined {
  if (typeof rule === 'string') return RISK_LEVEL[rule.toLowerCase()];
  if (rule && typeof rule === 'object') {
    const obj = rule as Record<string, unknown>;
    const star = obj['*'];
    if (typeof star === 'string') return RISK_LEVEL[star.toLowerCase()];
    // Take the most-permissive action across all globs
    let maxLevel: number | undefined;
    for (const v of Object.values(obj)) {
      if (typeof v !== 'string') continue;
      const lvl = RISK_LEVEL[v.toLowerCase()];
      if (lvl === undefined) continue;
      if (maxLevel === undefined || lvl > maxLevel) maxLevel = lvl;
    }
    return maxLevel;
  }
  return undefined;
}

function topLevelLevel(perm: unknown, key: string): number | undefined {
  if (typeof perm === 'string') return RISK_LEVEL[perm.toLowerCase()];
  if (perm && typeof perm === 'object') {
    return actionLevel((perm as Record<string, unknown>)[key]);
  }
  return undefined;
}

export const opc006 = defineCheck({
  id: 'OPC-006',
  name: 'OpenCode Sub-Agent Permission Downgrade',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Detect when an OpenCode sub-agent has weaker permissions than the top-level config',
  supportedAgents: ['opencode'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      const agents = config.data.agent;
      if (!agents || typeof agents !== 'object') continue;
      const topPerm = config.data.permission;

      for (const [name, agent] of Object.entries(agents as Record<string, unknown>)) {
        if (!agent || typeof agent !== 'object') continue;
        const subPerm = (agent as Record<string, unknown>).permission;
        if (subPerm === undefined) continue;

        for (const key of TRACKED_KEYS) {
          const top = topLevelLevel(topPerm, key);
          const sub = topLevelLevel(subPerm, key);
          if (top === undefined || sub === undefined) continue;
          if (sub > top) {
            evidence.push({
              file: config.filePath,
              snippet: `agent.${name}.permission.${key}`,
              detail: `Sub-agent "${name}" upgrades ${key} from "${levelName(top)}" to "${levelName(sub)}"`,
            });
          }
        }
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'OpenCode sub-agents do not loosen top-level permissions',
      failed: (n) => `Found ${n} OpenCode sub-agent permission downgrade(s)`,
      fixDescription: 'Remove the per-agent permission override or tighten it to match the top-level policy',
    });
  },
});

function levelName(level: number): string {
  return Object.keys(RISK_LEVEL).find(k => RISK_LEVEL[k] === level) ?? String(level);
}
