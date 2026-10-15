import { defineCheck } from '../../core/check-builder.js';
import { CODING_AGENTS } from '../../core/types.js';
import { NATIVE_POLICY_FRAMEWORKS } from './native-policy-frameworks.js';
import { fixFirstConfig } from '../../remediation/config-writer.js';
import { getNestedValue } from '../../core/utils.js';

/** Attempts per window past which OpenClaw's auth throttle stops mattering. */
const OPENCLAW_MAX_ATTEMPTS = 100;

export const cfg010 = defineCheck({
  id: 'CFG-010',
  name: 'No Rate Limiting',
  category: 'config',
  severity: 'warning',
  description: 'Check if rate limiting is configured for the gateway',
  // Atomic Agent has no gateway to rate-limit (its HTTP service is flag-configured).
  // The other frameworks listed have no rateLimit key; writing one breaks strict loaders.
  // Hermes and NemoClaw have no rate-limit setting either.
  excludedAgents: [...CODING_AGENTS, ...NATIVE_POLICY_FRAMEWORKS, 'hermes', 'nemoclaw'],

  async run(ctx, h) {
    // OpenClaw 2026.x throttles gateway auth by default (10 attempts per 60 s,
    // 5 min lockout); gateway.auth.rateLimit only tunes it, and the generic
    // rateLimit key this fix would write is rejected by its schema.
    if (ctx.installation.agent === 'openclaw') {
      // gateway.auth.rateLimit only tunes the default — but tuned far enough
      // (thousands of attempts, no lockout) it no longer stops brute force.
      for (const config of ctx.configs) {
        const rl = getNestedValue(config.data, 'gateway.auth.rateLimit');
        if (!rl || typeof rl !== 'object') continue;
        const { maxAttempts, windowMs, lockoutMs } = rl as Record<string, unknown>;
        const weak: string[] = [];
        if (typeof maxAttempts === 'number' && maxAttempts > OPENCLAW_MAX_ATTEMPTS) weak.push(`maxAttempts ${maxAttempts}`);
        if (typeof lockoutMs === 'number' && lockoutMs <= 0) weak.push('lockoutMs 0 (no lockout)');
        if (typeof windowMs === 'number' && windowMs > 0 && windowMs < 1000) weak.push(`windowMs ${windowMs}`);
        if (weak.length > 0) {
          return h.result({
            passed: false,
            message: `Gateway auth rate limit tuned too weak to stop brute force: ${weak.join(', ')}`,
            evidence: [{ file: config.filePath, snippet: `gateway.auth.rateLimit: ${JSON.stringify(rl)}`, detail: weak.join(', ') }],
            fixable: false,
            fixDescription: `Remove gateway.auth.rateLimit (default: 10 attempts per minute, 5 minute lockout) or keep maxAttempts ≤ ${OPENCLAW_MAX_ATTEMPTS} with a lockout`,
          });
        }
      }
      const tuned = ctx.configs.some(c => getNestedValue(c.data, 'gateway.auth.rateLimit') !== undefined);
      return h.passed(tuned
        ? 'Gateway auth rate limiting is configured (gateway.auth.rateLimit)'
        : 'Gateway auth attempts are rate-limited by OpenClaw\'s default (10 per minute, 5 minute lockout)');
    }
    let found = false;

    for (const config of ctx.configs) {
      const rateLimit = getNestedValue(config.data, 'rateLimit') ??
                        getNestedValue(config.data, 'gateway.rateLimit') ??
                        getNestedValue(config.data, 'security.rateLimit') ??
                        getNestedValue(config.data, 'rateLimiting') ??
                        config.data.RATE_LIMIT;

      if (rateLimit) {
        found = true;
        break;
      }
    }

    return h.result({
      passed: found,
      message: found
        ? 'Rate limiting is configured'
        : 'No rate limiting configured — gateway is vulnerable to abuse',
      // The fix writes into the first config file; without one there is nothing to fix
      fixable: ctx.configs.length > 0,
      fixDescription: 'Add rate limiting configuration',
    });
  },

  async fix(ctx) {
    const rateLimit = { max: 60, window: '1m' };
    return fixFirstConfig(ctx.configs, {
      checkId: 'CFG-010',
      env: 'RATE_LIMIT',
      path: 'rateLimit',
      value: rateLimit,
      envValue: '60/1m',
      message: 'Added rate limiting (60 requests per minute)',
      noConfigMessage: 'No config file found',
    });
  },
});
