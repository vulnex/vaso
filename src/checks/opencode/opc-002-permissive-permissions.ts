import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { buildBroadPaths, isBroadPath } from '../../analyzers/broad-paths.js';
import { DANGEROUS_COMMANDS } from '../devin/dev-001-broad-permissions.js';
import { actionMatches, isCatchAllResource, v1CatchAll, v1PermissionRules, v1ScopedAllows, v2Action, v2CatchAll, v2PermissionRules } from './schema.js';

/**
 * OpenCode's permission defaults (opencode.ai/docs/permissions): most tools
 * are "allow"; `external_directory` and `doom_loop` are "ask". Rules in an
 * object are pattern → action with the last match winning, so `"*"` is the
 * catch-all and other keys scope it.
 *
 * An explicit "allow" that restates a default changes nothing, so the
 * allow-by-default tools are judged on their effective state, set or not
 * (info: OpenCode runs them unconfirmed unless set to "ask"). Critical is
 * kept for loosening what OpenCode guards by default.
 *
 * V1 rules are judged on the merged permission (`v1PermissionRules`): key
 * order decides, so `{ bash: "ask", "*": "allow" }` allows bash.
 */
const ALLOW_BY_DEFAULT = ['bash', 'edit', 'task', 'webfetch'] as const;

/** `rm *` → rm, `/usr/bin/python3 -c *` → python. */
function commandFamily(pattern: string): string {
  const first = (pattern.trim().split(/\s+/)[0] ?? '').split('/').pop() ?? '';
  return first.replace(/^(python|ruby|perl|php|node)\d+(?:\.\d+)*$/, '$1');
}

/** `~/projects/*` → `~/projects`, `/**` → `/`. */
function globBase(pattern: string): string {
  const base = pattern.replace(/(?:\/\*{1,2})+$/, '').replace(/\*+$/, '');
  return base === '' ? '/' : base;
}

export const opc002 = defineCheck({
  id: 'OPC-002',
  name: 'OpenCode Permission Auto-Allow',
  category: 'coding-agent',
  severity: 'critical',
  description: 'Detect OpenCode permissions that let shell, edit, fetch or outside-workspace access run without confirmation',
  supportedAgents: ['opencode'],

  async run(ctx, h) {
    const critical: Evidence[] = [];
    const home = ctx.fs.homedir();
    const broad = buildBroadPaths(home, ctx.platform);
    const gated = new Set<string>();

    for (const config of ctx.configs) {
      // V2: ordered `permissions` rules, last match wins, base policy allows
      // everything (external_directory included)
      const v2 = v2PermissionRules(config.data.permissions);
      if (v2) {
        for (const k of ALLOW_BY_DEFAULT) {
          if (v2CatchAll(v2, v2Action(k)).effect !== 'allow') gated.add(k);
        }
        // A scoped allow after the action's catch-all ask/deny re-opens it
        for (const [action, judge] of [
          ['shell', (resource: string) => {
            const family = commandFamily(resource);
            return DANGEROUS_COMMANDS.has(family)
              ? `"${family}" runs without confirmation — shell execution, network egress or privilege escalation`
              : undefined;
          }],
          ['external_directory', (resource: string) => {
            const hit = isBroadPath(globBase(resource), broad, home);
            return hit ? `Outside-workspace access allowed for a path that ${hit.reason}` : undefined;
          }],
        ] as const) {
          const top = v2CatchAll(v2, action);
          if (top.effect === 'allow') continue;
          v2.forEach((r, i) => {
            if (i <= top.index || r.effect !== 'allow' || isCatchAllResource(r.resource) || !actionMatches(r.action, action)) return;
            const detail = judge(r.resource);
            if (detail) {
              critical.push({
                file: config.filePath,
                snippet: `permissions[${i}] = { action: "${r.action}", resource: "${r.resource}", effect: "allow" }`,
                detail,
              });
            }
          });
        }
      }
    }

    // V1 `permission`: judged as OpenCode merges it — the config files, then
    // $OPENCODE_CONFIG_CONTENT and $OPENCODE_PERMISSION over them, so a later
    // layer can re-open a tool an earlier one gates
    const rules = v1PermissionRules(ctx.configs) ?? [];
    const allowedBy = new Map<string, string>();
    for (const k of ALLOW_BY_DEFAULT) {
      const top = v1CatchAll(rules, k)?.rule;
      if (top && top.action !== 'allow') gated.add(k);
      else if (top) allowedBy.set(k, top.file);
    }

    const ext = v1CatchAll(rules, 'external_directory')?.rule;
    if (ext?.action === 'allow') {
      critical.push(ext.fromString
        ? { file: ext.file, detail: 'permission = "allow" — every tool runs without confirmation, including access outside the workspace' }
        : {
          file: ext.file,
          snippet: ext.key === 'external_directory' ? 'permission.external_directory = "allow"' : `permission["${ext.key}"] = "allow"`,
          detail: 'Files outside the project are read and written without confirmation (OpenCode asks by default)',
        });
    }
    for (const r of v1ScopedAllows(rules, 'external_directory')) {
      const hit = isBroadPath(globBase(r.pattern), broad, home);
      if (hit) {
        critical.push({
          file: r.file,
          snippet: `permission.external_directory["${r.pattern}"] = "allow"`,
          detail: `Outside-workspace access allowed for a path that ${hit.reason}`,
        });
      }
    }

    if (v1CatchAll(rules, 'bash')?.rule.action !== 'allow') {
      for (const r of v1ScopedAllows(rules, 'bash')) {
        const family = commandFamily(r.pattern);
        if (DANGEROUS_COMMANDS.has(family)) {
          critical.push({
            file: r.file,
            snippet: `permission.bash["${r.pattern}"] = "allow"`,
            detail: `"${family}" runs without confirmation — shell execution, network egress or privilege escalation`,
          });
        }
      }
    }

    const unconfirmed = ALLOW_BY_DEFAULT.filter(k => !gated.has(k));
    const evidence = [...critical];
    if (unconfirmed.length > 0) {
      evidence.push({
        file: unconfirmed.map(k => allowedBy.get(k)).find(f => f !== undefined) ?? ctx.configs[0]?.filePath ?? ctx.installation.installDir,
        snippet: `permission: ${unconfirmed.join(', ')} = "allow"`,
        detail: `${unconfirmed.join(', ')} run without confirmation — OpenCode's default unless set to "ask"`,
      });
    }

    return h.fromEvidence(evidence, {
      passed: 'OpenCode asks before running shell, edit, fetch and sub-agent tools',
      failed: (n) => `Found ${n} OpenCode permission(s) that run tools without confirmation`,
      severity: critical.length > 0 ? 'critical' : 'info',
      fixDescription: 'Set permission.bash and permission.edit to "ask" (allow specific commands with patterns), and keep external_directory on "ask" or scoped to specific paths',
    });
  },
});
