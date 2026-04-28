import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

const PUBLIC_HOSTS = new Set(['0.0.0.0', '::', '0:0:0:0:0:0:0:0']);

export const ly010 = defineCheck({
  id: 'LY-010',
  name: 'WebChat Unauthenticated and Non-Loopback',
  category: 'lyrie',
  severity: 'critical',
  description: 'Detect WebChat enabled with no auth token and bound to a non-loopback host — anyone reachable on the network can talk to the agent.',
  supportedAgents: ['lyrie'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    for (const config of ctx.configs) {
      const port = config.data.LYRIE_WEBCHAT_PORT as string | undefined;
      if (!port) continue;

      const host = (config.data.LYRIE_WEBCHAT_HOST as string | undefined) ?? '127.0.0.1';
      const authToken = config.data.LYRIE_WEBCHAT_AUTH_TOKEN as string | undefined;
      const hasAuth = typeof authToken === 'string' && authToken.trim() !== '' && !/^\$\{?[A-Z_]+\}?$/.test(authToken.trim());
      const isPublic = PUBLIC_HOSTS.has(host) || (!host.startsWith('127.') && host !== 'localhost' && host !== '::1');

      if (isPublic && !hasAuth) {
        evidence.push({
          file: config.filePath,
          detail: `WebChat bound to ${host}:${port} with no LYRIE_WEBCHAT_AUTH_TOKEN — agent is reachable unauthenticated`,
        });
      }
    }
    return h.fromEvidence(evidence, {
      passed: 'WebChat is loopback-only or has an auth token',
      failed: () => 'WebChat is reachable on a public interface without authentication',
      fixDescription: 'Set LYRIE_WEBCHAT_HOST=127.0.0.1, or set a strong LYRIE_WEBCHAT_AUTH_TOKEN and put TLS-terminating proxy in front',
    });
  },
});
