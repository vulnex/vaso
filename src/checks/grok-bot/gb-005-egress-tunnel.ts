import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { envFlag, isOwnSession, settingsConfig } from './shared.js';

export const gb005 = defineCheck({
  id: 'GB-005',
  name: 'Grok Bot Cloud Traffic Routed Through This Computer',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Detect Grok Bot "Route traffic through this computer" (egressTunnelEnabled: true) — the cloud computer\'s and cloud browser\'s traffic leaves through this machine\'s network and IP; with SAND_EGRESS_TUNNEL_ALLOW_PRIVATE=1 it can also reach private-network hosts',
  supportedAgents: ['grok-bot'],

  async run(ctx, h) {
    const config = settingsConfig(ctx);
    if (!config || config.data.egressTunnelEnabled !== true) {
      return h.passed('Grok Bot cloud traffic does not use this computer\'s network');
    }
    // Team policy mirrored into settings: false blocks the tunnel for the account
    if (config.data.localEgressAllowed === false) {
      return h.result({
        passed: false,
        severity: 'info',
        message: 'Grok Bot egress routing is on but blocked by team policy',
        evidence: [{ file: config.filePath, snippet: 'egressTunnelEnabled: true, localEgressAllowed: false', detail: 'Inactive while the admin keeps Allow Local Egress Routing off', mitigated: true }],
      });
    }

    const evidence: Evidence[] = [{
      file: config.filePath,
      snippet: 'egressTunnelEnabled: true',
      detail: 'The cloud agent browses and connects out with this machine\'s IP — prompt-injected content can reach services that trust this network',
    }];
    const allowPrivate = isOwnSession(ctx) && envFlag(ctx, 'SAND_EGRESS_TUNNEL_ALLOW_PRIVATE');
    if (allowPrivate) {
      evidence.push({
        file: '<process env>',
        snippet: 'SAND_EGRESS_TUNNEL_ALLOW_PRIVATE=1',
        detail: 'Private targets are allowed: the cloud agent can reach LAN hosts, localhost services and cloud metadata endpoints through this computer',
      });
    }
    return h.fromEvidence(evidence, {
      passed: '',
      failed: () => allowPrivate
        ? 'Grok Bot routes cloud traffic through this computer, private networks included'
        : 'Grok Bot routes cloud traffic through this computer',
      severity: allowPrivate ? 'critical' : undefined,
      fixDescription: 'Turn off Settings → Computer → Network → "Route traffic through this computer" unless the agent needs this network; never set SAND_EGRESS_TUNNEL_ALLOW_PRIVATE',
    });
  },
});
