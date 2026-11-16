import { defineCheck } from '../../core/check-builder.js';
import type { Evidence } from '../../core/types.js';
import { envNote } from '../../adapters/env-overrides.js';
import { gatewayPosture, mainConfig, tomlLine, writeMainConfig } from './zc-config.js';
import { mainConfigFixTargets } from './zc-config.js';

export const zc004 = defineCheck({
  id: 'ZC-004',
  name: 'Gateway Pairing Disabled',
  category: 'zeroclaw',
  severity: 'warning',
  description:
    'Detect [gateway] require_pairing=false — the gateway accepts every bearer token (fails open), so any caller can drive the agent; critical when the gateway is reachable beyond loopback or through a tunnel',
  supportedAgents: ['zeroclaw'],

  fixTargets: mainConfigFixTargets,

  async run(ctx, h) {
    const config = mainConfig(ctx.configs);
    if (!config) return h.passed('No ZeroClaw config.toml found');
    const gw = gatewayPosture(config.data);
    const evidence: Evidence[] = [];
    const reachable = gw.hostExposed || gw.allowPublicBind || gw.tunnelActive;

    if (!gw.requirePairing) {
      const where = gw.tunnelActive
        ? `published through the ${gw.tunnelProvider} tunnel`
        : gw.hostExposed
          ? `bound to ${gw.host}`
          : gw.allowPublicBind
            ? 'allowed to bind publicly (allow_public_bind=true)'
            : `on ${gw.host} (any local process or user can reach it)`;
      evidence.push({
        file: config.filePath,
        ...tomlLine(config.raw, 'gateway', 'require_pairing'),
        detail:
          `gateway.require_pairing = false${envNote(config.data, 'gateway.require_pairing')} — API, dashboard and /webhook accept unauthenticated requests; gateway ${where}` +
          (gw.webhookSecret ? '' : '; no gateway.webhook_secret either'),
      });
    }

    return h.fromEvidence(evidence, {
      passed: 'Gateway pairing is required',
      failed: () => 'Gateway pairing is disabled — unauthenticated callers can control the agent',
      severity: evidence.length > 0 && reachable ? 'critical' : undefined,
      fixable: true,
      fixDescription: 'Set [gateway] require_pairing = true and pair clients via the one-time pairing code',
    });
  },

  async fix(ctx) {
    return writeMainConfig(ctx, 'ZC-004', [['gateway.require_pairing', true]], 'Set gateway.require_pairing=true');
  },
});
