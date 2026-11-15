import { join } from 'node:path';
import type { Evidence, ParsedConfig, ScanContext } from '../../core/types.js';
import { stripJsonc } from '../../core/jsonc.js';
import { devinConfigDir } from '../../adapters/devin.js';
import { defineCheck } from '../../core/check-builder.js';
import { buildBroadPaths, isBroadPath } from '../../analyzers/broad-paths.js';
import { commandFamily } from '../../analyzers/command-families.js';

// Commands whose unrestricted Exec() allowance hands the agent arbitrary
// code execution or network egress.
export const DANGEROUS_COMMANDS = new Set([
  'curl', 'wget', 'bash', 'sh', 'zsh', 'fish', 'dash', 'ksh', 'pwsh',
  'perl', 'python', 'ruby', 'php', 'node', 'deno', 'bun',
  'npx', 'ssh', 'nc', 'ncat', 'sudo', 'su', 'doas', 'chmod', 'rm',
]);


// `Fetch(url)` scopes HTTP requests (Devin CLI permissions reference,
// e.g. `Fetch(https://internal.api/*)`); a wildcard host is any egress.
const ANY_URL = /^(?:\*{1,2}|(?:\*|https?):\/\/\*{1,2}(?:\/\*{0,2})?)$/i;

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

/** The user-level Devin configs a project install inherits (none for a user install). */
async function userConfigsForProject(ctx: ScanContext): Promise<ParsedConfig[]> {
  if (ctx.installation.profile !== 'project') return [];
  const dir = devinConfigDir(ctx.fs.homedir(), ctx.fs);
  const out: ParsedConfig[] = [];
  for (const name of ['config.json', 'mcp_config.json']) {
    const filePath = join(dir, name);
    try {
      if (!(await ctx.fs.access(filePath))) continue;
      const raw = await ctx.fs.readFile(filePath);
      out.push({ raw, format: 'json', filePath, data: JSON.parse(stripJsonc(raw)) as Record<string, unknown> });
    } catch {
      // unreadable or not JSON — contributes no deny rules
    }
  }
  return out;
}

export const dev001 = defineCheck({
  id: 'DEV-001',
  name: 'Devin Over-Broad Permission Rules',
  category: 'coding-agent',
  severity: 'critical',
  description: 'Detect Devin sessions starting in Bypass mode (permission_mode "dangerous", local_tools_bypass_permissions) and permission allow rules granting unrestricted execution (exec, Exec(*), edit, Write(**), Write(/**), Fetch(*), mcp__*, shell/network/interpreter commands) or an allow list with no deny guardrails',
  // Devin Desktop 3.x (windsurf adapter) reads the same ~/.config/devin/config.json permissions
  supportedAgents: ['devin', 'windsurf'],

  async run(ctx, h) {
    const criticalEvidence: Evidence[] = [];
    const warningEvidence: Evidence[] = [];
    const home = ctx.fs.homedir();
    // Scratch dirs (/tmp, /var/tmp) are routine write targets — only whole-disk,
    // whole-home, and /etc write grants are critical here.
    const broadPaths = buildBroadPaths(home).filter(b => !b.path.endsWith('tmp'));

    // Devin merges permission lists across config levels and deny wins at
    // any level, so a deny rule in any of this installation's files — or, for
    // a project install, in the user config — guards the allow rules.
    const hasAnyDeny = [...ctx.configs, ...await userConfigsForProject(ctx)].some(c => {
      const p = c.data.permissions as Record<string, unknown> | undefined;
      return Array.isArray(p?.deny) && p.deny.some(e => typeof e === 'string');
    });

    // User-only settings (docs.devin.ai/cli/reference/configuration/config-file):
    // permission_mode "dangerous" starts every local session in Bypass mode
    // (all tool calls auto-approved); local_tools_bypass_permissions starts
    // every local-tools connection (cloud session driving this machine) with
    // per-call prompts off. Project files can't set either.
    if (ctx.installation.agent === 'devin' && ctx.installation.profile !== 'project') {
      for (const config of ctx.configs) {
        const mode = config.data.permission_mode;
        if (typeof mode === 'string' && mode.trim().toLowerCase() === 'dangerous') {
          criticalEvidence.push({
            file: config.filePath,
            snippet: `permission_mode: "${mode}"`,
            detail: 'New sessions start in Bypass mode — every tool call (shell, writes, MCP) is auto-approved without a prompt',
          });
        } else if (typeof mode === 'string' && mode.trim().toLowerCase() === 'accept-edits') {
          // docs.devin.ai/cli/reference/permissions: workspace file edits
          // auto-approved; shell commands and outside writes still prompt
          warningEvidence.push({
            file: config.filePath,
            snippet: `permission_mode: "${mode}"`,
            detail: 'New sessions start in Accept Edits mode — workspace file edits are auto-approved without review (shell commands still prompt)',
          });
        } else if (typeof mode === 'string' && mode.trim().toLowerCase() === 'smart') {
          // Smart: Accept Edits plus a model that judges shell commands, web
          // fetches, MCP tools and outside writes, auto-running those it deems safe
          warningEvidence.push({
            file: config.filePath,
            snippet: `permission_mode: "${mode}"`,
            detail: 'New sessions start in Smart mode — workspace file edits are auto-approved, and a model decides which shell commands, fetches, MCP tool calls and outside writes run without a prompt',
          });
        }
        if (config.data.local_tools_bypass_permissions === true) {
          warningEvidence.push({
            file: config.filePath,
            snippet: 'local_tools_bypass_permissions: true',
            detail: 'Local-tools connections start with Bypass Permissions on — a cloud session runs commands on this machine without a per-call prompt (deny/ask rules still apply)',
          });
        }
      }
    }

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
              detail: `Write allow rule path ${broad.reason} — the agent may modify files there without approval`,
            });
            continue;
          }
        }

        if (action === 'fetch' && (unscoped || ANY_URL.test(rule.resource!))) {
          criticalEvidence.push({
            file: config.filePath,
            snippet: `permissions.allow: "${entry}"`,
            detail: 'Unrestricted Fetch allow — the agent may send HTTP requests to any host (data exfiltration) without approval',
          });
          continue;
        }

        if (action === 'exec' && rule.resource) {
          const cmd = execCommandName(rule.resource);
          if (DANGEROUS_COMMANDS.has(commandFamily(cmd))) {
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
      // Deny-gap alone is hygiene, not an exposure — info, as CC-008 rates
      // the same gap in Claude Code
      severity: criticalEvidence.length > 0 ? undefined
        : warningEvidence.some(e => e.snippet?.startsWith('local_tools_bypass_permissions') || e.snippet?.startsWith('permission_mode')) ? 'warning' : 'info',
      fixDescription: 'Set permission_mode to "normal" (not "dangerous", "smart" or "accept-edits") and local_tools_bypass_permissions, scope Exec()/Write() allow rules to specific commands and paths, and add deny rules for shells, network tools, and credential paths',
    });
  },
});
