import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { envFile, envString, envTrue, isConfigured, lyrieMergedEnvs } from './env.js';

function isLoopback(host: string): boolean {
  const h = host.replace(/^\[|\]$/g, '').toLowerCase();
  return h === 'localhost' || h === '::1' || h.startsWith('127.');
}

/**
 * gateway/src/index.ts: WebChat starts only with LYRIE_WEBCHAT_ENABLED=true;
 * host LYRIE_WEBCHAT_HOST (default 127.0.0.1), port LYRIE_WEBCHAT_PORT
 * (default 7777), auth LYRIE_WEBCHAT_TOKEN. In 3.4.0 the WebChat server is
 * a skeleton (Bun.serve commented out) and the token is not checked
 * anywhere, so this is configuration risk rather than a live listener.
 */
export const ly010 = defineCheck({
  id: 'LY-010',
  name: 'WebChat Enabled on Non-Loopback Host Without Token',
  category: 'lyrie',
  severity: 'warning',
  description: 'Detect LYRIE_WEBCHAT_ENABLED=true with LYRIE_WEBCHAT_HOST set to a non-loopback address and no LYRIE_WEBCHAT_TOKEN. Lyrie 3.4.0 ships the WebChat listener as a skeleton (nothing binds yet), so this is a latent exposure: the configuration asks for an unauthenticated chat endpoint reachable from the network.',
  supportedAgents: ['lyrie'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    for (const config of lyrieMergedEnvs(ctx.configs)) {
      if (!envTrue(config, 'LYRIE_WEBCHAT_ENABLED')) continue;

      const host = envString(config, 'LYRIE_WEBCHAT_HOST') || '127.0.0.1';
      if (isLoopback(host)) continue;
      if (isConfigured(envString(config, 'LYRIE_WEBCHAT_TOKEN'))) continue;

      const port = envString(config, 'LYRIE_WEBCHAT_PORT') || '7777';
      evidence.push({
        file: envFile(config, 'LYRIE_WEBCHAT_HOST'),
        snippet: `LYRIE_WEBCHAT_HOST=${host}`,
        detail: `WebChat enabled on ${host}:${port} with no LYRIE_WEBCHAT_TOKEN — anyone who can reach it could talk to the agent (the 3.4.0 WebChat listener is not wired yet, so nothing binds today)`,
      });
    }
    return h.fromEvidence(evidence, {
      passed: 'WebChat is disabled, loopback-only, or has a token',
      failed: () => 'WebChat configured on a network interface without authentication',
      fixDescription: 'Set LYRIE_WEBCHAT_HOST=127.0.0.1 (front it with an authenticating TLS proxy if remote access is needed), set a strong LYRIE_WEBCHAT_TOKEN, or remove LYRIE_WEBCHAT_ENABLED',
    });
  },
});
