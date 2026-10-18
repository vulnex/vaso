import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { envFlag, isOwnSession, settingsConfig } from './shared.js';

export const gb005 = defineCheck({
  id: 'GB-005',
  name: 'Grok Bot Cloud Traffic Routed Through This Computer',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Detect Grok Bot routing the cloud computer\'s traffic through this machine — "Route traffic through this computer" (egressTunnelEnabled: true), or a tunnel configured from the environment (SAND_EGRESS_TUNNEL_URL) — and SAND_EGRESS_TUNNEL_ALLOW_PRIVATE=1, which lets an environment-configured tunnel reach private-network hosts',
  supportedAgents: ['grok-bot'],

  async run(ctx, h) {
    const config = settingsConfig(ctx);
    const own = isOwnSession(ctx);
    // A tunnel configured from the environment (SAND_EGRESS_TUNNEL_URL + its
    // bearer) is the only one that honours SAND_EGRESS_TUNNEL_ALLOW_PRIVATE;
    // the settings-driven tunnel always keeps private targets off
    const envTunnel = own ? ctx.fs.getEnv('SAND_EGRESS_TUNNEL_URL')?.trim() : undefined;
    const allowPrivate = !!envTunnel && envFlag(ctx, 'SAND_EGRESS_TUNNEL_ALLOW_PRIVATE');
    const settingsTunnel = config?.data.egressTunnelEnabled === true;
    if (!settingsTunnel && !envTunnel) {
      return h.passed('Grok Bot cloud traffic does not use this computer\'s network');
    }

    const evidence: Evidence[] = [];
    if (settingsTunnel && config) {
      // Team policy mirrored into settings: false blocks the tunnel for the account
      const blocked = config.data.localEgressAllowed === false;
      evidence.push({
        file: config.filePath,
        snippet: blocked ? 'egressTunnelEnabled: true, localEgressAllowed: false' : 'egressTunnelEnabled: true',
        detail: blocked
          ? 'Inactive while the admin keeps Allow Local Egress Routing off'
          : 'The cloud agent browses and connects out with this machine\'s IP (public targets only) — prompt-injected content can reach services that trust this IP',
        mitigated: blocked || undefined,
      });
    }
    if (envTunnel) {
      evidence.push({
        file: '<process env>',
        snippet: allowPrivate ? 'SAND_EGRESS_TUNNEL_URL set, SAND_EGRESS_TUNNEL_ALLOW_PRIVATE=1' : 'SAND_EGRESS_TUNNEL_URL set',
        detail: allowPrivate
          ? 'Private targets allowed: the cloud agent can reach LAN hosts, localhost services and cloud metadata endpoints through this computer'
          : 'An environment-configured egress tunnel routes the cloud computer\'s traffic through this machine',
      });
    }
    return h.fromEvidence(evidence, {
      passed: '',
      failed: () => allowPrivate
        ? 'Grok Bot routes cloud traffic through this computer, private networks included'
        : 'Grok Bot routes cloud traffic through this computer',
      severity: allowPrivate ? 'critical' : undefined,
      fixDescription: 'Turn off Settings → Computer → Network → "Route traffic through this computer" unless the agent needs this network; unset SAND_EGRESS_TUNNEL_URL / SAND_EGRESS_TUNNEL_ALLOW_PRIVATE',
    });
  },
});
