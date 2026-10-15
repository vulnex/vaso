import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { isInsecureUrl, isLoopbackUrl, isProjectInstall, markUntrustedProject, settingsConfigs } from './shared.js';

const ABACUS_HOST = /^https:\/\/(?:[a-z0-9-]+\.)*abacus\.ai(?::\d+)?(?:\/|$)/i;

export const aba011 = defineCheck({
  id: 'ABA-011',
  name: 'Abacus.AI Insecure or Redirected API Endpoint',
  category: 'coding-agent',
  severity: 'critical',
  description: 'Detect an Abacus.AI baseUrl / ABACUS_BASE_URL or local-provider baseURL over plaintext http:// (credentials and code in cleartext), and a baseUrl pointing away from abacus.ai (the API key and every prompt go to that host)',
  supportedAgents: ['abacus'],

  async run(ctx, h) {
    const critical: Evidence[] = [];
    const warning: Evidence[] = [];

    const checkBase = (file: string, snippet: string, url: string) => {
      if (isInsecureUrl(url)) {
        critical.push({ file, snippet, detail: 'Plaintext http:// API endpoint — the Abacus.AI credential, prompts and code travel unencrypted' });
      } else if (/^https?:\/\//i.test(url) && !ABACUS_HOST.test(url) && !isLoopbackUrl(url)) {
        warning.push({ file, snippet, detail: 'API base URL is not an abacus.ai host — the stored credential and all session content are sent there' });
      }
    };

    for (const config of settingsConfigs(ctx.configs)) {
      if (typeof config.data.baseUrl === 'string') {
        checkBase(config.filePath, `baseUrl: ${config.data.baseUrl}`, config.data.baseUrl);
      }
      const providers = config.data.providers;
      if (providers && typeof providers === 'object' && !Array.isArray(providers)) {
        for (const [id, raw] of Object.entries(providers as Record<string, unknown>)) {
          const options = (raw as Record<string, unknown> | undefined)?.options as Record<string, unknown> | undefined;
          const url = options?.baseURL ?? options?.baseUrl;
          if (isInsecureUrl(url)) {
            critical.push({ file: config.filePath, snippet: `providers.${id}.options.baseURL: ${url}`, detail: `Plaintext http:// endpoint for provider "${id}" — its API key and prompts travel unencrypted` });
          }
        }
      }
    }
    await markUntrustedProject(ctx, critical);
    await markUntrustedProject(ctx, warning);

    if (!isProjectInstall(ctx)) {
      const envUrl = ctx.fs.getEnv('ABACUS_BASE_URL');
      if (envUrl) checkBase('<process env>', `ABACUS_BASE_URL=${envUrl}`, envUrl);
    }

    const liveCritical = critical.some(e => !e.mitigated);
    return h.fromEvidence([...critical, ...warning], {
      passed: 'Abacus.AI API endpoints use TLS and point at abacus.ai',
      failed: (n) => `Found ${n} insecure or redirected Abacus.AI endpoint(s)`,
      severity: liveCritical ? undefined : 'warning',
      fixDescription: 'Remove baseUrl / ABACUS_BASE_URL overrides (the default is https://apps.abacus.ai) and use https:// for local provider endpoints that are not on loopback',
    });
  },
});
