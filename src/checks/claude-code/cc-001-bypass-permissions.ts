import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { getNestedValue } from '../../core/utils.js';
import { compareVersions } from '../../core/semver.js';

const DANGEROUS_MODES = new Set(['bypassPermissions', 'acceptAll', 'dangerouslySkipPermissions']);

// Claude Code 2.1.257 changelog: "Changed defaultMode: \"bypassPermissions\" in
// .claude/settings.json or .claude/settings.local.json to be ignored, like
// \"auto\"; set it in user or managed settings, or pass --permission-mode".
// A repo can no longer switch its own approvals off.
const PROJECT_BYPASS_IGNORED_SINCE = '2.1.257';

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

      const skipFlag = config.data.dangerouslySkipPermissions;
      if (skipFlag === true) {
        evidence.push({
          file: config.filePath,
          detail: 'dangerouslySkipPermissions = true — agent will execute tools without approval',
        });
      }
    }

    // Project-scope bypass on an unknown/older version: real only on old
    // releases, so a warning rather than critical. User/managed scope (or the
    // skip flag) keeps the declared severity.
    const onlyProjectBypass = projectUnknown && evidence.every(e => !e.mitigated && e.detail?.includes('project settings'));
    return h.fromEvidence(evidence, {
      passed: 'Permission approval prompts are not bypassed',
      failed: () => projectIgnored && evidence.every(e => e.mitigated)
        ? 'Project settings request bypassPermissions, but this Claude Code version ignores it'
        : 'Permission bypass mode is enabled — Claude Code will execute tools without confirmation',
      severity: onlyProjectBypass ? 'warning' : undefined,
      fixDescription: 'Remove permissions.defaultMode = "bypassPermissions" or set it to "default"/"acceptEdits"',
    });
  },
});
