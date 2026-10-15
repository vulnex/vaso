import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { hermesApiServer, isLoopbackHost } from '../../adapters/hermes-api-server.js';

export const hm004 = defineCheck({
  id: 'HM-004',
  name: 'Hermes API Server Non-Loopback Without Auth Key',
  category: 'hermes',
  severity: 'critical',
  description: 'The API server host (API_SERVER_HOST or gateway.api_server.host) is non-loopback (e.g. 0.0.0.0) but no key is set (API_SERVER_KEY or gateway.api_server.key) — Hermes API server accepts unauthenticated requests with full access to the agent toolset (including terminal commands).',
  supportedAgents: ['hermes'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    const api = hermesApiServer(ctx.configs);
    if (api.host && !isLoopbackHost(api.host.value) && !api.key) {
      evidence.push({
        file: api.host.file ?? ctx.configs[0]?.filePath ?? '~/.hermes/.env',
        snippet: `${api.host.source}, API_SERVER_KEY=<unset>`,
        detail: 'API server bound to non-loopback address with no bearer token — anyone who can reach the host can run terminal commands',
      });
    }
    return h.fromEvidence(evidence, {
      passed: 'API server bound to loopback or has an authentication key configured',
      failed: () => 'Hermes API server is reachable without authentication',
      fixDescription: 'Set API_SERVER_KEY=<long-random-token> in ~/.hermes/.env (or gateway.api_server.key), or bind 127.0.0.1 behind a TLS reverse proxy',
    });
  },
});
