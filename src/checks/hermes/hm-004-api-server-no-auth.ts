import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { hermesApiServer, hermesApiServerState, isLoopbackHost, HERMES_API_DISABLED, HERMES_API_GUARDS } from '../../adapters/hermes-api-server.js';

export const hm004 = defineCheck({
  id: 'HM-004',
  name: 'Hermes API Server Non-Loopback Without Auth Key',
  category: 'hermes',
  severity: 'critical',
  description: `The API server host (API_SERVER_HOST or gateway.api_server.host) is non-loopback (e.g. 0.0.0.0) but no key is set (API_SERVER_KEY or gateway.api_server.key) — Hermes API server accepts unauthenticated requests with full access to the agent toolset (including terminal commands). Hermes ${HERMES_API_GUARDS.nonLoopbackKey}+ refuses to start such a server (${HERMES_API_GUARDS.anyKey}+ without a key at all), so only older releases are exposed.`,
  supportedAgents: ['hermes'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    const version = ctx.installation.version;
    const api = hermesApiServer(ctx.configs, version);
    const state = hermesApiServerState(api, version);
    if (state === 'disabled') return h.passed(HERMES_API_DISABLED);
    if (state === 'refused') {
      return h.passed(`Hermes ${version} refuses to start the API server without a usable API_SERVER_KEY`);
    }
    if (api.host && !isLoopbackHost(api.host.value) && !api.key && state !== 'authenticated') {
      evidence.push({
        file: api.host.file ?? ctx.configs[0]?.filePath ?? '~/.hermes/.env',
        snippet: `${api.host.source}, API_SERVER_KEY=<unset>`,
        detail: state === 'unknown'
          ? `API server set to a non-loopback address with no bearer token — Hermes ${HERMES_API_GUARDS.nonLoopbackKey}+ refuses to start it; older releases accept unauthenticated requests (Hermes version unknown)`
          : 'API server bound to non-loopback address with no bearer token — anyone who can reach the host can run terminal commands',
        ...(state === 'unknown' ? { mitigated: true } : {}),
      });
    }
    return h.fromEvidence(evidence, {
      passed: 'API server bound to loopback or has an authentication key configured',
      failed: () => state === 'unknown'
        ? 'Hermes API server would be reachable without authentication on releases before the start-up key guard'
        : 'Hermes API server is reachable without authentication',
      fixDescription: 'Set API_SERVER_KEY=<long-random-token> in ~/.hermes/.env (or gateway.api_server.key), or bind 127.0.0.1 behind a TLS reverse proxy',
    });
  },
});
