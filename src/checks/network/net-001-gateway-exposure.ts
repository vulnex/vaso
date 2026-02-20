import type { CheckModule, ScanContext, CheckResult } from '../../core/types.js';

export const net001: CheckModule = {
  id: 'NET-001',
  name: 'Gateway Internet Exposure',
  category: 'network',
  severity: 'critical',
  description: 'Check if the gateway is bound to a public address',

  async run(ctx: ScanContext): Promise<CheckResult> {
    const gw = ctx.installation.gateway;
    if (!gw?.host) {
      return { id: 'NET-001', name: 'Gateway Internet Exposure', category: 'network', severity: 'critical', passed: true, message: 'No gateway configured' };
    }

    const publicBind = gw.host === '0.0.0.0' || gw.host === '::';

    return {
      id: 'NET-001',
      name: 'Gateway Internet Exposure',
      category: 'network',
      severity: 'critical',
      passed: !publicBind,
      message: publicBind
        ? `Gateway bound to ${gw.host}:${gw.port ?? '?'} — exposed to all network interfaces`
        : `Gateway bound to ${gw.host} — not publicly exposed`,
    };
  },
};
