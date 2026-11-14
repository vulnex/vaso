import { basename, join } from 'node:path';
import { parseYamlSafe } from '../../core/yaml-safe.js';
import type { Evidence, ParsedConfig, ScanContext } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { actionMatches, v2Action, v2CatchAll, v2PermissionRules, type PermissionRule } from './schema.js';

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
    // `"*"` is the default for permissions not named
    const rules = perm as Record<string, unknown>;
    return actionLevel(rules[key] ?? rules['*']);
  }
  return undefined;
}

function mergedPermission(configs: ParsedConfig[]): unknown {
  let merged: unknown;
  for (const c of configs) {
    const p = c.data.permission;
    if (p === undefined) continue;
    merged = typeof p === 'object' && p && merged && typeof merged === 'object'
      ? { ...(merged as Record<string, unknown>), ...(p as Record<string, unknown>) }
      : p;
  }
  return merged;
}

async function markdownAgents(dirs: string[], ctx: ScanContext): Promise<string[]> {
  const files: string[] = [];
  for (const dir of dirs) {
    // Both agent/ and agents/ are read
    for (const sub of ['agent', 'agents']) {
      const agentDir = join(dir, sub);
      try {
        const names = await ctx.fs.readdir(agentDir);
        files.push(...names.filter(n => n.endsWith('.md')).sort().map(n => join(agentDir, n)));
      } catch {
        // no such directory
      }
    }
  }
  return files;
}

function frontmatter(content: string): Record<string, unknown> | undefined {
  const m = /^---\r?\n([\s\S]*?)\r?\n---(?:\r?\n|$)/.exec(content.replace(/^\uFEFF/, ''));
  if (!m) return undefined;
  try {
    const data = parseYamlSafe(m[1]);
    return data && typeof data === 'object' ? data as Record<string, unknown> : undefined;
  } catch {
    return undefined;
  }
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

    // Top-level permission as OpenCode merges it: later layers override
    const topPerm = mergedPermission(ctx.configs);

    const compare = (name: string, subPerm: unknown, file: string, where: string) => {
      for (const key of TRACKED_KEYS) {
        const top = topLevelLevel(topPerm, key);
        const sub = topLevelLevel(subPerm, key);
        if (top === undefined || sub === undefined) continue;
        if (sub > top) {
          evidence.push({
            file,
            snippet: `${where}.${key}`,
            detail: `Sub-agent "${name}" upgrades ${key} from "${levelName(top)}" to "${levelName(sub)}"`,
          });
        }
      }
    };

    // V2: agents.<id>.permissions are appended to the global `permissions`
    // rules (last match wins), so any agent rule for an action loosens it
    // when it allows more than the global catch-all
    const globalV2: PermissionRule[] = ctx.configs.flatMap(c => v2PermissionRules(c.data.permissions) ?? []);
    for (const config of ctx.configs) {
      const agents = config.data.agents;
      if (!agents || typeof agents !== 'object' || Array.isArray(agents)) continue;
      for (const [name, agent] of Object.entries(agents as Record<string, unknown>)) {
        const rules = v2PermissionRules((agent as Record<string, unknown> | null)?.permissions);
        if (!rules) continue;
        for (const key of TRACKED_KEYS) {
          const action = v2Action(key);
          const top = RISK_LEVEL[v2CatchAll(globalV2, action).effect];
          let sub: number | undefined;
          for (const r of rules) {
            if (!actionMatches(r.action, action)) continue;
            const lvl = RISK_LEVEL[r.effect];
            if (lvl !== undefined && (sub === undefined || lvl > sub)) sub = lvl;
          }
          if (top === undefined || sub === undefined || sub <= top) continue;
          evidence.push({
            file: config.filePath,
            snippet: `agents.${name}.permissions (${action})`,
            detail: `Sub-agent "${name}" upgrades ${action} from "${levelName(top)}" to "${levelName(sub)}"`,
          });
        }
      }
    }

    for (const config of ctx.configs) {
      const agents = config.data.agent;
      if (!agents || typeof agents !== 'object') continue;
      for (const [name, agent] of Object.entries(agents as Record<string, unknown>)) {
        if (!agent || typeof agent !== 'object') continue;
        const subPerm = (agent as Record<string, unknown>).permission;
        if (subPerm === undefined) continue;
        compare(name, subPerm, config.filePath, `agent.${name}.permission`);
      }
    }

    // Markdown agents: `permission:` in the frontmatter of agent(s)/<name>.md
    // under the config dir, $OPENCODE_CONFIG_DIR, or a project's .opencode/
    // (opencode.ai/docs/agents)
    const dirs = [ctx.installation.installDir];
    const extraDir = ctx.installation.profile !== 'project' ? ctx.fs.getEnv?.('OPENCODE_CONFIG_DIR')?.trim() : undefined;
    if (extraDir) dirs.push(extraDir);
    for (const file of await markdownAgents(dirs, ctx)) {
      let content: string;
      try {
        content = await ctx.fs.readFile(file);
      } catch {
        continue;
      }
      const subPerm = frontmatter(content)?.permission;
      if (subPerm === undefined) continue;
      compare(basename(file, '.md'), subPerm, file, 'frontmatter permission');
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
