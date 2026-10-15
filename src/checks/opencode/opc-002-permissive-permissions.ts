import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { buildBroadPaths, isBroadPath } from '../../analyzers/broad-paths.js';
import { DANGEROUS_COMMANDS } from '../devin/dev-001-broad-permissions.js';

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
 */
const ALLOW_BY_DEFAULT = ['bash', 'edit', 'task', 'webfetch'] as const;

/** The catch-all action of a rule: a string, or an object's `"*"`. */
function catchAll(rule: unknown): string | undefined {
  if (typeof rule === 'string') return rule.toLowerCase();
  if (rule && typeof rule === 'object') {
    const star = (rule as Record<string, unknown>)['*'];
    if (typeof star === 'string') return star.toLowerCase();
  }
  return undefined;
}

/** Scoped `pattern → "allow"` entries of an object rule (not the catch-all). */
function scopedAllows(rule: unknown): string[] {
  if (!rule || typeof rule !== 'object') return [];
  return Object.entries(rule as Record<string, unknown>)
    .filter(([pattern, action]) => pattern !== '*' && typeof action === 'string' && action.toLowerCase() === 'allow')
    .map(([pattern]) => pattern);
}

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
    const broad = buildBroadPaths(home);
    const gated = new Set<string>();

    for (const config of ctx.configs) {
      const perm = config.data.permission;
      if (typeof perm === 'string') {
        if (perm.toLowerCase() === 'allow') {
          critical.push({
            file: config.filePath,
            detail: 'permission = "allow" — every tool runs without confirmation, including access outside the workspace',
          });
        } else {
          for (const k of ALLOW_BY_DEFAULT) gated.add(k);
        }
        continue;
      }
      if (!perm || typeof perm !== 'object') continue;
      const rules = perm as Record<string, unknown>;
      const global = catchAll(rules['*']);

      for (const k of ALLOW_BY_DEFAULT) {
        const action = catchAll(rules[k]) ?? global;
        if (action && action !== 'allow') gated.add(k);
      }

      // external_directory is "ask" by default: allowing it is a real loosening
      const ext = catchAll(rules.external_directory) ?? (rules.external_directory === undefined ? global : undefined);
      if (ext === 'allow') {
        critical.push({
          file: config.filePath,
          snippet: rules.external_directory === undefined ? 'permission["*"] = "allow"' : 'permission.external_directory = "allow"',
          detail: 'Files outside the project are read and written without confirmation (OpenCode asks by default)',
        });
      }
      for (const pattern of scopedAllows(rules.external_directory)) {
        const hit = isBroadPath(globBase(pattern), broad, home);
        if (hit) {
          critical.push({
            file: config.filePath,
            snippet: `permission.external_directory["${pattern}"] = "allow"`,
            detail: `Outside-workspace access allowed for a path that ${hit.reason}`,
          });
        }
      }

      // A scoped bash allow only matters when bash isn't already allowed outright
      if ((catchAll(rules.bash) ?? global) !== 'allow') {
        for (const pattern of scopedAllows(rules.bash)) {
          const family = commandFamily(pattern);
          if (DANGEROUS_COMMANDS.has(family)) {
            critical.push({
              file: config.filePath,
              snippet: `permission.bash["${pattern}"] = "allow"`,
              detail: `"${family}" runs without confirmation — shell execution, network egress or privilege escalation`,
            });
          }
        }
      }
    }

    const unconfirmed = ALLOW_BY_DEFAULT.filter(k => !gated.has(k));
    const evidence = [...critical];
    if (unconfirmed.length > 0) {
      evidence.push({
        file: ctx.configs[0]?.filePath ?? ctx.installation.installDir,
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
