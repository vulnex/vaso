import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { envFlag, isProjectInstall } from './shared.js';

export const msc010 = defineCheck({
  id: 'MSC-010',
  name: 'Muse Code Safety Override in Environment',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Detect environment overrides that weaken Meta Muse Code for every session started from this shell: MUSE_PERMISSION_PROFILE_FAIL_OPEN=1 (a permission profile rule Muse cannot enforce runs unenforced instead of refusing) and MUSE_CUA_DEV_POLICY (computer-use app blocking switched to a development or external policy)',
  supportedAgents: ['muse-code'],

  async run(ctx, h) {
    if (isProjectInstall(ctx)) return h.passed('Environment overrides are evaluated on the user installation');
    const evidence: Evidence[] = [];
    if (envFlag(ctx, 'MUSE_PERMISSION_PROFILE_FAIL_OPEN')) {
      evidence.push({
        file: '<process env>',
        snippet: `MUSE_PERMISSION_PROFILE_FAIL_OPEN=${ctx.fs.getEnv('MUSE_PERMISSION_PROFILE_FAIL_OPEN')}`,
        detail: 'Permission-profile rules Muse cannot enforce are ignored instead of refusing the session — the profile silently grants more than it says',
      });
    }
    const cua = ctx.fs.getEnv('MUSE_CUA_DEV_POLICY')?.trim();
    if (cua) {
      evidence.push({
        file: '<process env>',
        snippet: `MUSE_CUA_DEV_POLICY=${cua.slice(0, 40)}`,
        detail: /^dangerous/i.test(cua)
          ? 'Computer-use blocking is OFF — the agent may operate any app, including password managers and banking'
          : 'Computer-use app/site blocking follows a development policy instead of the built-in security rules',
      });
    }
    return h.fromEvidence(evidence, {
      passed: 'No Muse Code safety overrides in the environment',
      failed: (n) => `Found ${n} Muse Code safety override(s) in the environment`,
      fixDescription: 'Unset MUSE_PERMISSION_PROFILE_FAIL_OPEN and MUSE_CUA_DEV_POLICY in shell profiles and service environments; fix the profile rule Muse reports instead',
    });
  },
});
