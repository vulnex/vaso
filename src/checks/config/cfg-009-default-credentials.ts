import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

export const WEAK_PATTERNS = [
  /\bpassword\b/i,
  /\b(admin|root|test|demo|default|changeme|password123|12345|qwerty)\b/i,
  // Values copied from documentation and never replaced:
  // "replace-with-long-random-token", "your_token_here", "<token>", "xxxx…",
  // and the sequential "abcd1234efgh5678" style of example secrets
  /(?:^|[-_ .])(?:replace|change|your|insert|enter|example|placeholder|sample|dummy)(?:[-_ .]|$)/i,
  /^<[^>]+>$/,
  /^x{4,}$/i,
  /abcd1234|12345678|0123456789/i,
];

/** `${OPENCLAW_GATEWAY_TOKEN}`-style references are resolved at runtime, not credentials. */
const ENV_REFERENCE = /^\$\{?[A-Za-z_][A-Za-z0-9_]*\}?$/;

const CREDENTIAL_KEYS = ['password', 'secret', 'token', 'api_key', 'apiKey', 'auth_token'];

import { getNestedValue } from '../../core/utils.js';
import type { ScanContext } from '../../core/types.js';
import { openclawGatewayExposed } from '../openclaw/oc-008-dangerous-gateway-overrides.js';
import { containerEnvironment } from '../../adapters/openclaw-bind.js';

/**
 * Provably reachable only from this host: OpenClaw's own exposure rule (bind
 * mode, custom host, Tailscale serve/funnel), else the detected gateway's
 * host. Unknown exposure counts as reachable.
 */
function loopbackOnly(ctx: ScanContext, inContainer: boolean | undefined): boolean {
  const host = ctx.installation.gateway?.host;
  const loopbackHost = typeof host === 'string' && /^(?:127(?:\.\d{1,3}){3}|::1|\[::1\]|localhost)$/i.test(host.trim());
  if (ctx.installation.agent === 'openclaw') {
    // Both must say local: OpenClaw's bind rule, and any host the adapter
    // detected (an older config's `gateway.host: 0.0.0.0` is not loopback)
    return !ctx.configs.some(c => openclawGatewayExposed(c.data, inContainer)) && (host === undefined || loopbackHost);
  }
  return loopbackHost;
}

export const cfg009 = defineCheck({
  id: 'CFG-009',
  name: 'Default/Weak Credentials',
  category: 'config',
  severity: 'critical',
  description: 'Check for default or weak credentials in config files',

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      // Check structured data for known credential keys
      for (const key of CREDENTIAL_KEYS) {
        const paths = [key, `auth.${key}`, `gateway.auth.${key}`, `security.${key}`];
        for (const path of paths) {
          const value = getNestedValue(config.data, path);
          if (typeof value === 'string' && !ENV_REFERENCE.test(value.trim())) {
            for (const pattern of WEAK_PATTERNS) {
              if (pattern.test(value)) {
                evidence.push({
                  file: config.filePath,
                  detail: `Weak credential in "${path}": value matches common default pattern`,
                });
                break;
              }
            }
          }
        }
      }
    }

    // A guessable token matters as far as the gateway it guards can be reached
    const local = evidence.length > 0 && loopbackOnly(ctx, ctx.installation.agent === 'openclaw' ? await containerEnvironment(ctx.fs) : undefined);
    return h.fromEvidence(evidence, {
      passed: 'No default or weak credentials found',
      failed: (n) => `Found ${n} default/weak credential(s)${local ? ' (gateway reachable from this host only)' : ''}`,
      severity: local ? 'warning' : 'critical',
    });
  },
});
