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

export const hm005 = defineCheck({
  id: 'HM-005',
  name: 'Hermes API Server Permissive CORS',
  category: 'hermes',
  severity: 'warning',
  description: 'API_SERVER_HOST is non-loopback and API_SERVER_CORS_ORIGINS is empty or "*" — any browser tab on any origin can call the Hermes API.',
  supportedAgents: ['hermes'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    const host = readEnvKey(ctx.configs, 'API_SERVER_HOST');
    if (!host || LOOPBACK_HOSTS.has(host)) {
      return h.fromEvidence(evidence, {
        passed: 'API server is loopback-only — CORS config not relevant',
        failed: () => 'unreachable',
      });
    }
    const origins = readEnvKey(ctx.configs, 'API_SERVER_CORS_ORIGINS');
    const envFile = ctx.configs.find(c => c.format === 'env')?.filePath ?? '~/.hermes/.env';
    if (!origins) {
      evidence.push({
        file: envFile,
        detail: 'API_SERVER_CORS_ORIGINS unset — Hermes accepts cross-origin requests with no origin allowlist',
      });
    } else if (origins === '*' || origins.split(',').map(s => s.trim()).includes('*')) {
      evidence.push({
        file: envFile,
        snippet: `API_SERVER_CORS_ORIGINS=${origins}`,
        detail: 'API_SERVER_CORS_ORIGINS contains "*" — any browser origin can drive the Hermes API',
      });
    }
    return h.fromEvidence(evidence, {
      passed: 'API server CORS allowlist is restrictive',
      failed: () => 'API_SERVER_CORS_ORIGINS is unset or wildcard',
      fixDescription: 'Set API_SERVER_CORS_ORIGINS to an explicit comma-separated list of frontend origins (e.g. https://your-app.example.com)',
    });
  },
});
