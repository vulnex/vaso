import { defineCheck } from '../../core/check-builder.js';
import { falsy, isLegacy, isLegacyUnused, legacySetting, str } from './layout.js';

/*
 * 0.x only. The orchestrator's internal worker API (sandbox containers call
 * back into it) listens on ORCHESTRATOR_PORT (default 50051). On Linux it binds
 * 0.0.0.0 unconditionally so Docker-bridge containers can reach it
 * (src/orchestrator/api.rs); macOS/Windows bind loopback. There is no host
 * setting — ORCHESTRATOR_HOST, which this check used to read and write, does
 * not exist. Requests carry per-job bearer tokens, so this is by-design
 * exposure worth firewalling, not an open door. 1.x has no orchestrator.
 */

export const ic003 = defineCheck({
  id: 'IC-003',
  name: 'Orchestrator Worker API On All Interfaces (0.x)',
  category: 'ironclaw',
  severity: 'info',
  description: 'On Linux, IronClaw 0.x binds the orchestrator worker API (ORCHESTRATOR_PORT, default 50051) to 0.0.0.0 whenever the Docker sandbox is enabled',
  supportedAgents: ['ironclaw'],

  async run(ctx, h) {
    if (!isLegacy(ctx)) return h.passed('Not applicable to IronClaw 1.x (no orchestrator listener)');
    if (isLegacyUnused(ctx)) return h.passed('0.x configuration is not used by the installed IronClaw 1.x binary');
    if ((ctx.fs?.platform ?? ctx.platform) !== 'linux') {
      return h.passed('Orchestrator binds loopback on macOS/Windows');
    }
    const disabled = legacySetting(ctx, 'SANDBOX_ENABLED', 'sandbox.enabled').some(s => falsy(s.value));
    if (disabled) return h.passed('Docker sandbox is disabled — orchestrator is not started');

    const port = legacySetting(ctx, 'ORCHESTRATOR_PORT').map(s => str(s.value)).find(Boolean) ?? '50051';
    return h.result({
      passed: false,
      message: `Orchestrator worker API listens on 0.0.0.0:${port} (Linux, sandbox enabled)`,
      evidence: [{
        file: ctx.installation.installDir,
        detail: `IronClaw 0.x binds the orchestrator on all interfaces on Linux so sandbox containers can reach it; port ${port} is reachable from the network unless firewalled`,
      }],
      fixDescription: `Firewall TCP ${port} to the Docker bridge (e.g. allow only 172.17.0.0/16), or upgrade to IronClaw 1.x`,
    });
  },
});
