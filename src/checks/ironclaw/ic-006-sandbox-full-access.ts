import type { Evidence, FixResult } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { updateConfigValue, updateEnvFile } from '../../remediation/config-writer.js';
import {
  isLegacy, isLegacyUnused, legacySetting, lineOf, rebornConfig, rebornProfileSources, rebornServiceUnits, str, table, truthy,
} from './layout.js';
import { configFixTargets } from '../../remediation/fix-refusal.js';

/*
 * 1.x: boot profile `local-dev-yolo` (StandaloneUnrestricted) grants
 * "trusted-laptop" host access — host-home filesystem, local host process
 * execution, direct network and the inherited environment (secrets). It is
 * selected by [boot].profile or $IRONCLAW_REBORN_PROFILE (env wins) and needs
 * `--confirm-host-access` at runtime.
 * 0.x: SANDBOX_POLICY=full_access runs commands directly on the host, but only
 * with the second opt-in SANDBOX_ALLOW_FULL_ACCESS=true — without it the
 * manager refuses to execute (src/sandbox/manager.rs).
 */

const YOLO = 'local-dev-yolo';
const FULL_ACCESS = new Set(['full_access', 'fullaccess', 'full', 'none']);

export const ic006 = defineCheck({
  id: 'IC-006',
  name: 'Unrestricted Host Access Profile',
  category: 'ironclaw',
  severity: 'critical',
  description: 'Check for the 1.x local-dev-yolo boot profile (unrestricted host filesystem, process, network and environment access) or the 0.x SANDBOX_POLICY=full_access + SANDBOX_ALLOW_FULL_ACCESS=true double opt-in',
  supportedAgents: ['ironclaw'],

  fixTargets: configFixTargets,

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    let fixable = false;

    if (!isLegacy(ctx)) {
      for (const src of await rebornProfileSources(ctx)) {
        if (src.profile !== YOLO) continue;
        if (src.via === '[boot].profile') fixable = true;
        evidence.push({
          file: src.file,
          ...(src.line ? { line: src.line } : {}),
          detail: `${src.via} = ${YOLO} — the agent gets host-home filesystem access, host process execution, direct network and the inherited environment`,
        });
      }
      for (const unit of await rebornServiceUnits(ctx)) {
        const idx = unit.raw.split('\n').findIndex(l => l.includes('--confirm-host-access'));
        if (idx >= 0) {
          evidence.push({
            file: unit.file,
            line: idx + 1,
            detail: 'Service starts `ironclaw serve --confirm-host-access` — unrestricted host access is pre-confirmed',
          });
        }
      }
    } else if (!isLegacyUnused(ctx)) {
      const policies = legacySetting(ctx, 'SANDBOX_POLICY', 'sandbox.policy')
        .filter(s => FULL_ACCESS.has((str(s.value) ?? '').toLowerCase()));
      const allowed = legacySetting(ctx, 'SANDBOX_ALLOW_FULL_ACCESS').some(s => truthy(s.value));
      if (policies.length > 0 && allowed) {
        fixable = true;
        for (const s of policies) {
          const line = lineOf(s.config, s.config.format === 'env' ? s.key : 'policy');
          evidence.push({
            file: s.file,
            ...(line ? { line } : {}),
            detail: `${s.key} = ${String(s.value)} with SANDBOX_ALLOW_FULL_ACCESS=true — sandboxed commands run directly on the host`,
          });
        }
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'No unrestricted host-access profile is configured',
      failed: () => 'IronClaw is configured for unrestricted host access',
      fixable,
      fixDescription: isLegacy(ctx)
        ? 'Set SANDBOX_POLICY=readonly (or workspace_write) and remove SANDBOX_ALLOW_FULL_ACCESS'
        : 'Use the local-dev profile: set [boot].profile = "local-dev", unset IRONCLAW_REBORN_PROFILE=local-dev-yolo and drop --confirm-host-access from the service',
    });
  },

  async fix(ctx): Promise<FixResult> {
    if (!isLegacy(ctx)) {
      const config = rebornConfig(ctx);
      if (config && str(table(config.data.boot)?.profile) === YOLO) {
        await updateConfigValue(config, 'boot.profile', 'local-dev');
        return { checkId: 'IC-006', applied: true, message: 'Set [boot].profile = "local-dev" (check IRONCLAW_REBORN_PROFILE and service units, which override it)' };
      }
      return { checkId: 'IC-006', applied: false, message: 'local-dev-yolo is selected outside config.toml (environment or service unit) — change it there' };
    }
    if (isLegacyUnused(ctx)) return { checkId: 'IC-006', applied: false, message: '0.x configuration is not in use' };
    let applied = 0;
    for (const s of legacySetting(ctx, 'SANDBOX_POLICY', 'sandbox.policy')) {
      if (!FULL_ACCESS.has((str(s.value) ?? '').toLowerCase())) continue;
      if (s.config.format === 'env') await updateEnvFile(s.file, 'SANDBOX_POLICY', 'readonly');
      else await updateConfigValue(s.config, 'sandbox.policy', 'readonly');
      applied++;
    }
    return applied > 0
      ? { checkId: 'IC-006', applied: true, message: 'Set the sandbox policy to readonly' }
      : { checkId: 'IC-006', applied: false, message: 'No full_access sandbox policy found' };
  },
});
