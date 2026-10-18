import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { hermesApiServer, hermesApiServerState, isLoopbackHost, HERMES_API_DISABLED } from '../../adapters/hermes-api-server.js';

export const hm005 = defineCheck({
  id: 'HM-005',
  name: 'Hermes API Server Permissive CORS',
  category: 'hermes',
  severity: 'warning',
  description: 'The API server is non-loopback and its CORS origins (API_SERVER_CORS_ORIGINS or gateway.api_server.cors_origins) contain "*" — any browser tab on any origin can call the Hermes API. Unset origins are safe: Hermes then sends no CORS headers.',
  supportedAgents: ['hermes'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    const api = hermesApiServer(ctx.configs, ctx.installation.version);
    const state = hermesApiServerState(api, ctx.installation.version);
    if (state === 'disabled') return h.passed(HERMES_API_DISABLED);
    if (state === 'refused') {
      return h.passed(`Hermes ${ctx.installation.version} refuses to start the API server without a usable API_SERVER_KEY`);
    }
    if (!api.host || isLoopbackHost(api.host.value)) {
      return h.passed('API server is loopback-only — CORS config not relevant');
    }
    const origins = api.corsOrigins;
    if (origins && origins.value.split(',').map(s => s.trim()).includes('*')) {
      evidence.push({
        file: origins.file ?? ctx.configs[0]?.filePath ?? '~/.hermes/.env',
        snippet: origins.source,
        detail: 'CORS origins contain "*" — any browser origin can drive the Hermes API',
      });
    }
    return h.fromEvidence(evidence, {
      passed: origins ? 'API server CORS allowlist is restrictive' : 'API server CORS is off (no origins configured)',
      failed: () => 'Hermes API server allows every browser origin',
      fixDescription: 'List the frontend origins explicitly in API_SERVER_CORS_ORIGINS (or remove it to disable browser access)',
    });
  },
});
