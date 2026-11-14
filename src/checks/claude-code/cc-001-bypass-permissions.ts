import { join } from 'node:path';
import type { Evidence, ScanContext } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { getNestedValue } from '../../core/utils.js';
import { compareVersions } from '../../core/semver.js';
import { parseJsonLenient } from '../../core/jsonc.js';
import { claudeConfigPaths, claudeManagedSettingsPaths } from '../../adapters/claude-code.js';
import { readSubagents } from './subagents.js';

// The documented modes are default, acceptEdits, plan, auto, dontAsk and
// bypassPermissions (code.claude.com/docs/en/permission-modes); only the last
// skips approval.
const DANGEROUS_MODES = new Set(['bypassPermissions']);

// Sub-agent frontmatter `permissionMode: bypassPermissions` takes effect only
// when the main conversation already bypasses, from Claude Code 2.1.267
// (code.claude.com/docs/en/sub-agents "Permission modes"); before that a
// sub-agent could switch approvals off on its own.
const SUBAGENT_BYPASS_GATED_SINCE = '2.1.267';

// Claude Code 2.1.257 changelog: "Changed defaultMode: \"bypassPermissions\" in
// .claude/settings.json or .claude/settings.local.json to be ignored, like
// \"auto\"; set it in user or managed settings, or pass --permission-mode".
// A repo can no longer switch its own approvals off.
const PROJECT_BYPASS_IGNORED_SINCE = '2.1.257';

/** `permissions.disableBypassPermissionsMode`: "disable" (documented) or true. */
function disablesBypass(data: unknown): boolean {
  const v = getNestedValue((data ?? {}) as Record<string, unknown>, 'permissions.disableBypassPermissionsMode');
  return v === 'disable' || v === true;
}

/**
 * The settings file that switches bypass mode off, if any. The key is a lock
 * honoured from any file (code.claude.com/docs/en/settings-reference), so a
 * project install also counts the user's and the managed settings.
 */
async function bypassDisabledBy(ctx: ScanContext): Promise<string | undefined> {
  const hit = ctx.configs.find(c => disablesBypass(c.data));
  if (hit) return hit.filePath;
  if (ctx.installation.profile !== 'project') return undefined;
  const { claudeDir } = claudeConfigPaths(ctx.fs.homedir(), ctx.fs);
  const files = [join(claudeDir, 'settings.json'), join(claudeDir, 'settings.local.json'), ...await claudeManagedSettingsPaths(ctx.fs)];
  for (const file of files) {
    try {
      if (disablesBypass(parseJsonLenient(await ctx.fs.readFile(file)))) return file;
    } catch {
      // absent or unreadable
    }
  }
  return undefined;
}

export const cc001 = defineCheck({
  id: 'CC-001',
  name: 'Permission Bypass Mode',
  category: 'coding-agent',
  severity: 'critical',
  description: 'Detect when Claude Code is configured to bypass tool approval prompts',
  supportedAgents: ['claude-code'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    const project = ctx.installation.profile === 'project';
    const version = ctx.installation.version;
    const projectIgnored = project && !!version && compareVersions(version, PROJECT_BYPASS_IGNORED_SINCE) >= 0;
    let projectUnknown = false;
    const autoMode: Evidence[] = [];

    for (const config of ctx.configs) {
      const mode = getNestedValue(config.data, 'permissions.defaultMode') as string | undefined;
      if (mode && DANGEROUS_MODES.has(mode)) {
        if (projectIgnored) {
          evidence.push({
            file: config.filePath,
            detail: `permissions.defaultMode = "${mode}" in project settings — ignored by Claude Code ${version} (>= ${PROJECT_BYPASS_IGNORED_SINCE} only honors bypass from user/managed settings or --permission-mode)`,
            mitigated: true,
          });
        } else {
          if (project) projectUnknown = true;
          evidence.push({
            file: config.filePath,
            detail: project
              ? `permissions.defaultMode = "${mode}" in project settings — honored by Claude Code < ${PROJECT_BYPASS_IGNORED_SINCE} (installed version unknown or older): tool executions skip user confirmation`
              : `permissions.defaultMode = "${mode}" — all tool executions skip user confirmation`,
          });
        }
      }

      // Auto mode: a classifier model reviews actions instead of you. It is
      // the built-in default on current versions and is ignored in project
      // settings, so an explicit user/managed value is informational.
      if (mode === 'auto' && !project) {
        autoMode.push({
          file: config.filePath,
          detail: 'permissions.defaultMode = "auto" — a classifier reviews tool calls instead of prompting you (not a bypass; deny rules still apply). Set permissions.disableAutoMode: "disable" in managed settings to require prompts',
          mitigated: true,
        });
      }

      const skipFlag = config.data.dangerouslySkipPermissions;
      if (skipFlag === true) {
        evidence.push({
          file: config.filePath,
          detail: 'dangerouslySkipPermissions = true — agent will execute tools without approval',
        });
      }
    }

    // Sub-agents asking for bypassPermissions in their frontmatter
    const subagentGated = !!version && compareVersions(version, SUBAGENT_BYPASS_GATED_SINCE) >= 0;
    for (const agent of await readSubagents(ctx)) {
      const pm = agent.frontmatter.permissionMode;
      if (typeof pm !== 'string' || !DANGEROUS_MODES.has(pm)) continue;
      evidence.push(subagentGated
        ? {
          file: agent.file,
          detail: `Sub-agent permissionMode = "${pm}" — Claude Code ${version} (>= ${SUBAGENT_BYPASS_GATED_SINCE}) runs it in bypass only when the main conversation already is`,
          mitigated: true,
        }
        : {
          file: agent.file,
          detail: `Sub-agent permissionMode = "${pm}" — honored by Claude Code < ${SUBAGENT_BYPASS_GATED_SINCE} (installed version unknown or older): the sub-agent's tool calls skip confirmation`,
        });
    }

    // disableBypassPermissionsMode removes bypass mode (and
    // --dangerously-skip-permissions) whatever requests it
    const disabledBy = evidence.length > 0 ? await bypassDisabledBy(ctx) : undefined;
    if (disabledBy) {
      for (const e of evidence) {
        e.mitigated = true;
        e.detail = `${e.detail} — inactive: permissions.disableBypassPermissionsMode is set in ${disabledBy}`;
      }
    }

    // Project-scope bypass on an unknown/older version: real only on old
    // releases, so a warning rather than critical. User/managed scope (or the
    // skip flag) keeps the declared severity.
    const live = evidence.filter(e => !e.mitigated);
    const onlyProjectBypass = projectUnknown && live.length > 0 && live.every(e => e.detail?.includes('project settings'));
    const onlyAuto = evidence.length === 0 && autoMode.length > 0;
    evidence.push(...autoMode);
    return h.fromEvidence(evidence, {
      passed: 'Permission approval prompts are not bypassed',
      failed: () => onlyAuto
        ? 'Claude Code starts in auto mode — a classifier, not you, approves tool calls'
        : disabledBy
        ? 'Settings request bypassPermissions, but permissions.disableBypassPermissionsMode blocks it'
        : projectIgnored && evidence.every(e => e.mitigated)
        ? 'Project settings request bypassPermissions, but this Claude Code version ignores it'
        : 'Permission bypass mode is enabled — Claude Code will execute tools without confirmation',
      severity: onlyProjectBypass ? 'warning' : undefined,
      fixDescription: 'Remove permissions.defaultMode = "bypassPermissions" or set it to "default"/"acceptEdits"',
    });
  },
});
