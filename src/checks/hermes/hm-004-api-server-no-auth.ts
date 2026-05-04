import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

const LOOPBACK_HOSTS = new Set(['127.0.0.1', 'localhost', '::1', '[::1]']);

function readEnvKey(configs: Array<{ format: string; data: Record<string, unknown> }>, key: string): string | undefined {
  for (const c of configs) {
    if (c.format !== 'env') continue;
    const v = c.data[key];
    if (typeof v === 'string' && v.trim()) return v.trim();
  }
  return undefined;
}

export const hm004 = defineCheck({
  id: 'HM-004',
  name: 'Hermes API Server Non-Loopback Without Auth Key',
  category: 'hermes',
  severity: 'critical',
  description: 'API_SERVER_HOST is non-loopback (e.g. 0.0.0.0) but API_SERVER_KEY is empty/unset — Hermes API server accepts unauthenticated requests with full access to the agent toolset (including terminal commands).',
  supportedAgents: ['hermes'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    const host = readEnvKey(ctx.configs, 'API_SERVER_HOST');
    const key = readEnvKey(ctx.configs, 'API_SERVER_KEY');
    if (host && !LOOPBACK_HOSTS.has(host) && !key) {
      const envFile = ctx.configs.find(c => c.format === 'env')?.filePath ?? '~/.hermes/.env';
      evidence.push({
        file: envFile,
        snippet: `API_SERVER_HOST=${host}, API_SERVER_KEY=<unset>`,
        detail: 'API server bound to non-loopback address with no bearer token — anyone who can reach the host can run terminal commands',
      });
    }
    return h.fromEvidence(evidence, {
      passed: 'API server bound to loopback or has an authentication key configured',
      failed: () => 'Hermes API server is reachable without authentication',
      fixDescription: 'Set API_SERVER_KEY=<long-random-token> in ~/.hermes/.env, or rebind API_SERVER_HOST=127.0.0.1 and use a reverse proxy with TLS',
    });
  },
});
