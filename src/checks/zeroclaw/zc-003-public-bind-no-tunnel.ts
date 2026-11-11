import { defineCheck } from '../../core/check-builder.js';
import type { Evidence } from '../../core/types.js';
import { gatewayPosture, mainConfig, tomlLine, writeMainConfig } from './zc-config.js';

export const zc003 = defineCheck({
  id: 'ZC-003',
  name: 'Gateway Exposed Without TLS or Tunnel',
  category: 'zeroclaw',
  severity: 'warning',
  description:
    'Detect a gateway bound beyond loopback ([gateway] host, or allow_public_bind=true for `--host` binds) with no tunnel and no [gateway.tls] — pairing codes and bearer tokens travel in cleartext; critical when pairing is also disabled',
  supportedAgents: ['zeroclaw'],

  async run(ctx, h) {
    const config = mainConfig(ctx.configs);
    if (!config) return h.passed('No ZeroClaw config.toml found');
    const gw = gatewayPosture(config.data);
    const evidence: Evidence[] = [];

    if ((gw.hostExposed || gw.allowPublicBind) && !gw.tunnelActive && !gw.tlsEnabled) {
      if (gw.hostExposed) {
        evidence.push({
          file: config.filePath,
          ...tomlLine(config.raw, 'gateway', 'host'),
          detail: `gateway.host = ${gw.host} — gateway listens beyond loopback with tunnel_provider=none and TLS disabled`,
        });
      }
      if (gw.allowPublicBind) {
        // With a loopback [gateway] host the switch only matters for a
        // `--host` given on the command line: the configured listener stays local
        evidence.push({
          file: config.filePath,
          ...tomlLine(config.raw, 'gateway', 'allow_public_bind'),
          detail: gw.hostExposed
            ? 'gateway.allow_public_bind = true — non-loopback binds (e.g. `zeroclaw gateway start --host 0.0.0.0`) are accepted without a tunnel or TLS'
            : `gateway.allow_public_bind = true — the configured host ${gw.host} is loopback; only a \`--host\` override on the command line would bind beyond it, without a tunnel or TLS`,
          ...(gw.hostExposed ? {} : { mitigated: true }),
        });
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'Gateway is loopback-only, tunnelled, or TLS-protected',
      failed: () => 'Gateway is exposed beyond loopback without TLS or a tunnel',
      severity: evidence.length > 0 && !gw.hostExposed ? 'info' : evidence.length > 0 && !gw.requirePairing ? 'critical' : undefined,
      fixable: true,
      fixDescription:
        'Set [gateway] host = "127.0.0.1" and allow_public_bind = false, or front the gateway with a tunnel ([tunnel] tunnel_provider) / enable [gateway.tls]',
    });
  },

  async fix(ctx) {
    return writeMainConfig(
      ctx,
      'ZC-003',
      [['gateway.host', '127.0.0.1'], ['gateway.allow_public_bind', false]],
      'Set gateway.host=127.0.0.1 and gateway.allow_public_bind=false',
    );
  },
});
