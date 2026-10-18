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
    const data = config?.data ?? {};
    // The app's switch: egressTunnelPreference, else egressTunnelEnabled — off
    // means no tunnel at all, from settings or the environment
    const pref = typeof data.egressTunnelPreference === 'boolean' ? data.egressTunnelPreference : data.egressTunnelEnabled;
    if (pref !== true) return h.passed('Grok Bot cloud traffic does not use this computer\'s network');

    const own = isOwnSession(ctx);
    // An environment tunnel replaces the box tunnel only with both its URL
    // and its bearer set; only it honours SAND_EGRESS_TUNNEL_ALLOW_PRIVATE
    const envUrl = own ? ctx.fs.getEnv('SAND_EGRESS_TUNNEL_URL')?.trim() : undefined;
    const envTunnel = !!envUrl && !!(own && ctx.fs.getEnv('SAND_EGRESS_TUNNEL_BEARER')?.trim());
    const allowPrivate = envTunnel && envFlag(ctx, 'SAND_EGRESS_TUNNEL_ALLOW_PRIVATE');
    const file = config?.filePath ?? '<process env>';
    const switchSnippet = typeof data.egressTunnelPreference === 'boolean' ? 'egressTunnelPreference: true' : 'egressTunnelEnabled: true';

    // Team policy mirrored into settings: false blocks the tunnel for the account
    if (data.localEgressAllowed === false) {
      return h.fromEvidence([{
        file, snippet: `${switchSnippet}, localEgressAllowed: false`,
        detail: 'Inactive while the admin keeps Allow Local Egress Routing off', mitigated: true,
      }], { passed: '', failed: () => 'Grok Bot egress routing is on but blocked by team policy' });
    }

    const evidence: Evidence[] = [{
      file,
      snippet: envTunnel
        ? `${switchSnippet}; SAND_EGRESS_TUNNEL_URL + SAND_EGRESS_TUNNEL_BEARER set${allowPrivate ? ', SAND_EGRESS_TUNNEL_ALLOW_PRIVATE=1' : ''}`
        : switchSnippet,
      detail: allowPrivate
        ? 'An environment-configured tunnel with private targets allowed: the cloud agent can reach LAN hosts, localhost services and cloud metadata endpoints through this computer'
        : envTunnel
          ? 'An environment-configured tunnel routes the cloud computer\'s traffic through this machine (public targets only)'
          : 'The cloud agent browses and connects out with this machine\'s IP (public targets only) — prompt-injected content can reach services that trust this IP',
    }];
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
