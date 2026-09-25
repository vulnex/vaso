import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { buildBroadPaths, isBroadPath } from '../../analyzers/broad-paths.js';

// Commands whose unrestricted Exec() allowance hands the agent arbitrary
// code execution or network egress.
export const DANGEROUS_COMMANDS = new Set([
  'curl', 'wget', 'bash', 'sh', 'zsh', 'perl', 'python', 'node',
  'npx', 'ssh', 'sudo', 'chmod', 'rm',
]);

// Bare `**` is cwd-relative (workspace-wide); broad absolute/home globs such as
// `/**` or `~/**` are resolved via the shared broad-path catalogue.
const WILDCARD_RESOURCES = new Set(['*', '**']);

// `mcp__*` auto-approves every tool on every configured MCP server.
const ALL_MCP_TOOLS = 'mcp__*';

interface ParsedRule {
  action: string;
  resource?: string;
}

/** Parse Devin's `Action(resource)` permission syntax; bare `Action` allowed. */
export function parseRule(entry: string): ParsedRule | undefined {
  const m = /^([A-Za-z_]+)\s*(?:\((.*)\))?$/.exec(entry.trim());
  if (!m) return undefined;
  return { action: m[1], resource: m[2]?.trim() };
}

/** Strip trailing glob segments: `/**` → `/`, `~/**` → `~`, `/tmp/*` → `/tmp`. */
function globBase(resource: string): string {
  const base = resource.replace(/(?:\/\*{1,2})+$/, '');
  return base === '' ? '/' : base;
}

/** First token of an Exec resource, path-stripped: `Exec(/bin/bash -c)` → `bash`. */
export function execCommandName(resource: string): string {
  const first = resource.split(/\s+/)[0] ?? '';
  return first.split('/').pop() ?? first;
}

export const dev001 = defineCheck({
  id: 'DEV-001',
  name: 'Devin Over-Broad Permission Rules',
  category: 'coding-agent',
  severity: 'critical',
  description: 'Detect Devin permission allow rules granting unrestricted execution (exec, Exec(*), edit, Write(**), Write(/**), mcp__*, shell/network commands) or an allow list with no deny guardrails',
  // Devin Desktop 3.x (windsurf adapter) reads the same ~/.config/devin/config.json permissions
  supportedAgents: ['devin', 'windsurf'],

  async run(ctx, h) {
    const criticalEvidence: Evidence[] = [];
    const warningEvidence: Evidence[] = [];
    const home = ctx.fs.homedir();
    // Scratch dirs (/tmp, /var/tmp) are routine write targets — only whole-disk,
    // whole-home, and /etc write grants are critical here.
    const broadPaths = buildBroadPaths(home).filter(b => !b.path.endsWith('tmp'));

    // Devin merges permission lists across config levels, so a deny rule in
    // any of this installation's files guards the allow rules in the others.
    const hasAnyDeny = ctx.configs.some(c => {
      const p = c.data.permissions as Record<string, unknown> | undefined;
      return Array.isArray(p?.deny) && p.deny.some(e => typeof e === 'string');
    });

    for (const config of ctx.configs) {
      const permissions = config.data.permissions as Record<string, unknown> | undefined;
      if (!permissions || typeof permissions !== 'object') continue;

      const allow = Array.isArray(permissions.allow)
        ? (permissions.allow as unknown[]).filter((e): e is string => typeof e === 'string')
        : [];

      for (const entry of allow) {
        if (entry.trim() === ALL_MCP_TOOLS) {
          criticalEvidence.push({
            file: config.filePath,
            snippet: `permissions.allow: "${entry}"`,
            detail: 'Allow rule for every MCP tool on every server — any tool a server exposes (including ones added later) runs without approval',
          });
          continue;
        }

        const rule = parseRule(entry);
        if (!rule) continue;
        // Scope rules are capitalized (`Exec(...)`), tool rules lowercase (`exec`)
        const action = rule.action.toLowerCase();
        const unscoped = rule.resource === undefined || rule.resource === '';

        if (action === 'exec' && (unscoped || WILDCARD_RESOURCES.has(rule.resource!))) {
          criticalEvidence.push({
            file: config.filePath,
            snippet: `permissions.allow: "${entry}"`,
            detail: 'Unrestricted Exec wildcard — the agent may run any command without approval',
          });
          continue;
        }

        if ((action === 'edit' || action === 'write') && unscoped) {
          criticalEvidence.push({
            file: config.filePath,
            snippet: `permissions.allow: "${entry}"`,
            detail: 'Unrestricted file-edit tool allow — the agent may modify any file, inside or outside the workspace, without approval',
          });
          continue;
        }

        if (action === 'write' && rule.resource) {
          if (WILDCARD_RESOURCES.has(rule.resource)) {
            criticalEvidence.push({
              file: config.filePath,
              snippet: `permissions.allow: "${entry}"`,
              detail: 'Unrestricted Write wildcard — the agent may modify any file in the workspace (including .devin/ config and hooks) without approval',
            });
            continue;
          }
          const broad = isBroadPath(globBase(rule.resource), broadPaths, home);
          if (broad) {
            criticalEvidence.push({
              file: config.filePath,
              snippet: `permissions.allow: "${entry}"`,
              detail: `Write allow rule ${broad.reason} — the agent may modify files there without approval`,
            });
            continue;
          }
        }

        if (action === 'exec' && rule.resource) {
          const cmd = execCommandName(rule.resource);
          if (DANGEROUS_COMMANDS.has(cmd)) {
            criticalEvidence.push({
              file: config.filePath,
              snippet: `permissions.allow: "${entry}"`,
              detail: `Allow rule for dangerous command "${cmd}" — grants shell execution, network egress, or privilege escalation without approval`,
            });
          }
        }
      }

      if (allow.length > 0 && !hasAnyDeny) {
        warningEvidence.push({
          file: config.filePath,
          snippet: `permissions.allow has ${allow.length} rule(s), deny is empty`,
          detail: 'Allow list present with no deny rules — nothing is explicitly blocked as a guardrail',
        });
      }
    }

    const evidence = [...criticalEvidence, ...warningEvidence];
    return h.fromEvidence(evidence, {
      passed: 'No over-broad Devin permission rules detected',
      failed: (n) => `Found ${n} over-broad Devin permission finding(s)`,
      // Deny-gap alone is a hygiene warning, not a critical exposure
      severity: criticalEvidence.length === 0 ? 'warning' : undefined,
      fixDescription: 'Scope Exec()/Write() allow rules to specific commands and paths, and add deny rules for shells, network tools, and credential paths',
    });
  },
});
