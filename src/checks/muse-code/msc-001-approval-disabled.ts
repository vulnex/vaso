import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { fixEveryConfig } from '../../remediation/config-writer.js';
import { configFixTargets } from '../../remediation/fix-refusal.js';
import { DEFAULT_PROFILE, defaultProfile, isProjectInstall, otherProfiles } from './shared.js';

export const msc001 = defineCheck({
  id: 'MSC-001',
  name: 'Muse Code Sessions Start Without Approval',
  category: 'coding-agent',
  severity: 'critical',
  description: 'Detect a Meta Muse Code default permission profile (settings.json permissions.default_profile) whose approval is allow_all — ":unrestricted" or a custom profile with approval "allow_all" / reviewer "none": every shell command, edit and MCP tool call runs without a prompt or review',
  supportedAgents: ['muse-code'],

  fixTargets: configFixTargets,

  async run(ctx, h) {
    if (isProjectInstall(ctx)) return h.passed('Permission profiles are user-level — evaluated on the user installation');
    const evidence: Evidence[] = [];
    const view = defaultProfile(ctx.configs);
    if (view?.configured && view.profile.approval === 'allow_all') {
      evidence.push({
        file: view.config.filePath,
        snippet: `permissions.default_profile: "${view.id}"`,
        detail: `Every session starts with approval allow_all and no reviewer${view.profile.filesystem === 'unrestricted' ? ', outside the filesystem sandbox' : ''} — the same as --yolo on every run`,
      });
    }
    // Profiles a session can opt into with --permission-profile: informational
    for (const p of otherProfiles(ctx.configs)) {
      if (p.profile.approval !== 'allow_all') continue;
      evidence.push({
        file: p.config.filePath,
        snippet: `permissions.profiles.${p.id}: approval allow_all`,
        detail: `Selectable profile "${p.id}" runs everything without approval (only with --permission-profile ${p.id})`,
        mitigated: true,
      });
    }
    return h.fromEvidence(evidence, {
      passed: 'Muse Code sessions start with approval prompts',
      failed: (n) => `Found ${n} Muse Code permission profile(s) that skip approval`,
      fixable: evidence.some(e => !e.mitigated),
      fixDescription: `Set permissions.default_profile to "${DEFAULT_PROFILE}" (Muse's default: prompts reviewed by the approval judge, sandboxed filesystem and proxied network) or ":read-only"; use --yolo for a single run when needed`,
    });
  },

  async fix(ctx) {
    const view = defaultProfile(ctx.configs);
    const configs = view?.configured && view.profile.approval === 'allow_all' ? [view.config] : [];
    return fixEveryConfig(configs, {
      checkId: 'MSC-001',
      path: ['permissions', 'default_profile'],
      value: DEFAULT_PROFILE,
      message: `Set permissions.default_profile to "${DEFAULT_PROFILE}"`,
      noConfigMessage: 'settings.json does not set a default profile that skips approval',
    });
  },
});
