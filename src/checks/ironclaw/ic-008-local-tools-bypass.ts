import type { Evidence, FixResult } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { updateEnvFile } from '../../remediation/config-writer.js';
import { isLegacy, isLegacyUnused, legacySetting, lineOf, truthy } from './layout.js';

/*
 * 0.x only: ALLOW_LOCAL_TOOLS=true (env-only, default false) registers the
 * shell/file tools in the orchestrator process even while the Docker sandbox
 * is enabled, so they run on the host outside the worker containers.
 */

export const ic008 = defineCheck({
  id: 'IC-008',
  name: 'Local Tools Outside Sandbox (0.x)',
  category: 'ironclaw',
  severity: 'warning',
  description: 'Check if IronClaw 0.x ALLOW_LOCAL_TOOLS=true runs tools on the host outside the Docker sandbox',
  supportedAgents: ['ironclaw'],

  async run(ctx, h) {
    if (!isLegacy(ctx)) return h.passed('Not applicable to IronClaw 1.x');
    if (isLegacyUnused(ctx)) return h.passed('0.x configuration is not used by the installed IronClaw 1.x binary');

    const evidence: Evidence[] = [];
    for (const s of legacySetting(ctx, 'ALLOW_LOCAL_TOOLS')) {
      if (!truthy(s.value)) continue;
      const line = lineOf(s.config, s.key);
      evidence.push({
        file: s.file,
        ...(line ? { line } : {}),
        detail: 'ALLOW_LOCAL_TOOLS=true — shell and file tools run in the host process outside the sandbox boundary',
      });
    }

    return h.fromEvidence(evidence, {
      passed: 'Local tools bypass is not enabled',
      failed: () => 'Local tools bypass is enabled — tools can execute outside the sandbox',
      fixable: true,
      fixDescription: 'Set ALLOW_LOCAL_TOOLS=false in ~/.ironclaw/.env',
    });
  },

  async fix(ctx): Promise<FixResult> {
    if (!isLegacy(ctx) || isLegacyUnused(ctx)) {
      return { checkId: 'IC-008', applied: false, message: 'Not applicable' };
    }
    const hits = legacySetting(ctx, 'ALLOW_LOCAL_TOOLS').filter(s => truthy(s.value));
    for (const s of hits) await updateEnvFile(s.file, 'ALLOW_LOCAL_TOOLS', 'false');
    return hits.length > 0
      ? { checkId: 'IC-008', applied: true, message: 'Set ALLOW_LOCAL_TOOLS=false' }
      : { checkId: 'IC-008', applied: false, message: 'ALLOW_LOCAL_TOOLS is not enabled' };
  },
});
