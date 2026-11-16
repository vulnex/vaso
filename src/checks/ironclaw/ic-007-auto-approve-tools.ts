import type { Evidence, FixResult } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { updateConfigValue, updateEnvFile } from '../../remediation/config-writer.js';
import {
  isLegacy, isLegacyUnused, legacySetting, lineOf, rebornConfig, rebornSection, str, truthy,
} from './layout.js';
import { configFixTargets } from '../../remediation/fix-refusal.js';

/*
 * 0.x: AGENT_AUTO_APPROVE_TOOLS (env) / [agent].auto_approve_tools
 * (config.toml overlay) skips every tool-approval prompt.
 * 1.x: [policy].default_approval_policy selects ApprovalPolicy — one of
 * ask_always / ask_writes / ask_destructive / org_policy / minimal. `minimal`
 * is the weakest posture. The [policy] section is only accepted with the
 * production / migration-dry-run boot profiles, and 1.4 parses but does not
 * yet enforce it ("parsed but not wired in this runtime slice", verified live
 * on 1.4.0) — so it is informational, with no fix to offer (changing it
 * changes nothing today), while the 0.x flag is live and critical.
 */

const WEAK_POLICIES = new Set(['minimal']);

export const ic007 = defineCheck({
  id: 'IC-007',
  name: 'Tool Approval Bypass',
  category: 'ironclaw',
  severity: 'critical',
  description: 'Check for 0.x AGENT_AUTO_APPROVE_TOOLS=true (all tool calls skip approval) or a 1.x [policy].default_approval_policy of "minimal"',
  supportedAgents: ['ironclaw'],

  fixTargets: configFixTargets,

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    let severity: 'critical' | 'info' = 'critical';

    if (!isLegacy(ctx)) {
      const config = rebornConfig(ctx);
      const policy = str(rebornSection(ctx, 'policy')?.default_approval_policy);
      if (config && policy && WEAK_POLICIES.has(policy.toLowerCase())) {
        severity = 'info';
        const line = lineOf(config, 'default_approval_policy');
        evidence.push({
          file: config.filePath,
          ...(line ? { line } : {}),
          snippet: `default_approval_policy = "${policy}"`,
          detail: '[policy].default_approval_policy = "minimal" — the weakest approval posture once enforced; IronClaw 1.4 parses [policy] but does not apply it yet',
        });
      }
    } else if (!isLegacyUnused(ctx)) {
      for (const s of legacySetting(ctx, 'AGENT_AUTO_APPROVE_TOOLS', 'agent.auto_approve_tools')) {
        if (!truthy(s.value)) continue;
        const line = lineOf(s.config, s.config.format === 'env' ? s.key : 'auto_approve_tools');
        evidence.push({
          file: s.file,
          ...(line ? { line } : {}),
          detail: `${s.key} = ${String(s.value)} — every tool call (shell, file writes, HTTP) runs without user approval`,
        });
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'Tool approval is not bypassed',
      failed: () => isLegacy(ctx)
        ? 'Tool auto-approval is enabled — tool calls bypass user confirmation'
        : 'Approval policy is set to "minimal" (not enforced by IronClaw 1.4 yet)',
      severity,
      fixable: isLegacy(ctx),
      fixDescription: isLegacy(ctx)
        ? 'Set AGENT_AUTO_APPROVE_TOOLS=false in ~/.ironclaw/.env (or [agent] auto_approve_tools = false)'
        : 'Set [policy].default_approval_policy = "ask_destructive" (or stricter)',
    });
  },

  async fix(ctx): Promise<FixResult> {
    if (!isLegacy(ctx)) {
      const config = rebornConfig(ctx);
      const policy = str(rebornSection(ctx, 'policy')?.default_approval_policy);
      if (config && policy && WEAK_POLICIES.has(policy.toLowerCase())) {
        await updateConfigValue(config, 'policy.default_approval_policy', 'ask_destructive');
        return { checkId: 'IC-007', applied: true, message: 'Set [policy].default_approval_policy = "ask_destructive"' };
      }
      return { checkId: 'IC-007', applied: false, message: 'No minimal approval policy found' };
    }
    if (isLegacyUnused(ctx)) return { checkId: 'IC-007', applied: false, message: '0.x configuration is not in use' };
    let applied = 0;
    for (const s of legacySetting(ctx, 'AGENT_AUTO_APPROVE_TOOLS', 'agent.auto_approve_tools')) {
      if (!truthy(s.value)) continue;
      if (s.config.format === 'env') await updateEnvFile(s.file, 'AGENT_AUTO_APPROVE_TOOLS', 'false');
      else await updateConfigValue(s.config, 'agent.auto_approve_tools', false);
      applied++;
    }
    return applied > 0
      ? { checkId: 'IC-007', applied: true, message: 'Disabled tool auto-approval' }
      : { checkId: 'IC-007', applied: false, message: 'No auto-approve setting found' };
  },
});
