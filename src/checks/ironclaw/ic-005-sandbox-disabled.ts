import type { Evidence, FixResult } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { updateConfigValue, updateEnvFile } from '../../remediation/config-writer.js';
import { falsy, isLegacy, isLegacyUnused, legacySetting, lineOf } from './layout.js';

/*
 * 0.x: SANDBOX_ENABLED (env) / [sandbox].enabled (config.toml overlay),
 * default true. When false, IronClaw registers its shell/file tools in the
 * main process instead of Docker workers (app.rs: `allow_local_tools ||
 * !sandbox.enabled`) — tool calls still go through approval, hence warning.
 * 1.x has no sandbox toggle: process isolation is chosen by boot profile
 * (see IC-006 for the unrestricted one).
 */

export const ic005 = defineCheck({
  id: 'IC-005',
  name: 'Docker Sandbox Disabled (0.x)',
  category: 'ironclaw',
  severity: 'warning',
  description: 'Check if the IronClaw 0.x Docker sandbox is disabled (SANDBOX_ENABLED=false / [sandbox].enabled = false), running tools on the host',
  supportedAgents: ['ironclaw'],

  async run(ctx, h) {
    if (!isLegacy(ctx)) return h.passed('Not applicable to IronClaw 1.x (isolation is selected by boot profile — see IC-006)');
    if (isLegacyUnused(ctx)) return h.passed('0.x configuration is not used by the installed IronClaw 1.x binary');

    const evidence: Evidence[] = [];
    for (const s of legacySetting(ctx, 'SANDBOX_ENABLED', 'sandbox.enabled')) {
      if (!falsy(s.value)) continue;
      const line = lineOf(s.config, s.config.format === 'env' ? s.key : 'enabled');
      evidence.push({
        file: s.file,
        ...(line ? { line } : {}),
        detail: `${s.key} = ${String(s.value)} — shell and file tools run in the IronClaw process on the host instead of Docker workers`,
      });
    }

    return h.fromEvidence(evidence, {
      passed: 'Docker sandbox is not disabled',
      failed: () => 'Docker sandbox is disabled — tools execute on the host',
      fixable: true,
      fixDescription: 'Set SANDBOX_ENABLED=true in ~/.ironclaw/.env (or [sandbox] enabled = true in config.toml)',
    });
  },

  async fix(ctx): Promise<FixResult> {
    let applied = 0;
    if (isLegacy(ctx) && !isLegacyUnused(ctx)) {
      for (const s of legacySetting(ctx, 'SANDBOX_ENABLED', 'sandbox.enabled')) {
        if (!falsy(s.value)) continue;
        if (s.config.format === 'env') await updateEnvFile(s.file, 'SANDBOX_ENABLED', 'true');
        else await updateConfigValue(s.config, 'sandbox.enabled', true);
        applied++;
      }
    }
    return applied > 0
      ? { checkId: 'IC-005', applied: true, message: 'Enabled the Docker sandbox' }
      : { checkId: 'IC-005', applied: false, message: 'No disabled sandbox setting found' };
  },
});
