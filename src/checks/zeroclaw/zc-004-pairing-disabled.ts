import type { CheckModule, ScanContext, CheckResult } from '../../core/types.js';
import { getNestedValue } from '../../core/utils.js';

export const zc004: CheckModule = {
  id: 'ZC-004',
  name: 'Pairing Disabled',
  category: 'zeroclaw',
  severity: 'warning',
  description: 'Detect require_pairing=false which allows unauthenticated device connections',
  supportedAgents: ['zeroclaw'],

  async run(ctx: ScanContext): Promise<CheckResult> {
    const evidence = [];

    for (const config of ctx.configs) {
      const requirePairing =
        getNestedValue(config.data, 'require_pairing') ??
        config.data.REQUIRE_PAIRING;

      if (requirePairing === false || requirePairing === 'false') {
        evidence.push({
          file: config.filePath,
          detail: 'require_pairing=false — any device can connect without authentication',
        });
      }
    }

    return {
      id: 'ZC-004',
      name: 'Pairing Disabled',
      category: 'zeroclaw',
      severity: 'warning',
      passed: evidence.length === 0,
      message: evidence.length === 0
        ? 'Device pairing is required'
        : 'Device pairing is disabled — unauthenticated connections allowed',
      evidence: evidence.length > 0 ? evidence : undefined,
      fixable: true,
      fixDescription: 'Set require_pairing=true to enforce device authentication',
    };
  },
};
