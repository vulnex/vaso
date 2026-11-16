import { defineCheck } from '../../core/check-builder.js';
import type { Evidence } from '../../core/types.js';
import { asRecord, isTrue, mainConfig, tomlLine, writeMainConfig, type Rec } from './zc-config.js';
import { mainConfigFixTargets } from './zc-config.js';

interface Finding {
  key: string;
  detail: string;
  fix: unknown;
}

function findings(gw: Rec): Finding[] {
  const out: Finding[] = [];
  if (isTrue(gw.allow_self_upgrade)) {
    out.push({
      key: 'allow_self_upgrade',
      detail: 'gateway.allow_self_upgrade = true — any paired dashboard client can replace the running zeroclaw binary',
      fix: false,
    });
  }
  if (isTrue(gw.trust_forwarded_headers)) {
    out.push({
      key: 'trust_forwarded_headers',
      detail: 'gateway.trust_forwarded_headers = true — clients can spoof X-Forwarded-For to evade per-client pairing/webhook rate limits unless a trusted reverse proxy rewrites it',
      fix: false,
    });
  }
  if (isTrue(gw.allow_remote_admin)) {
    out.push({
      key: 'allow_remote_admin',
      detail: 'gateway.allow_remote_admin = true — paired non-loopback callers may use admin endpoints (POST /admin/reload)',
      fix: false,
    });
  }
  if (gw.pair_rate_limit_per_minute === 0) {
    out.push({
      key: 'pair_rate_limit_per_minute',
      detail: 'gateway.pair_rate_limit_per_minute = 0 — /pair is not rate limited (pairing-code brute force)',
      fix: 10,
    });
  }
  if (gw.webhook_rate_limit_per_minute === 0) {
    out.push({
      key: 'webhook_rate_limit_per_minute',
      detail: 'gateway.webhook_rate_limit_per_minute = 0 — /webhook is not rate limited',
      fix: 60,
    });
  }
  return out;
}

export const zc016 = defineCheck({
  id: 'ZC-016',
  name: 'Gateway Hardening Relaxed',
  category: 'zeroclaw',
  severity: 'warning',
  description:
    'Detect relaxed [gateway] safeguards: allow_self_upgrade, trust_forwarded_headers, allow_remote_admin, or pairing/webhook rate limiting disabled (0)',
  supportedAgents: ['zeroclaw'],

  fixTargets: mainConfigFixTargets,

  async run(ctx, h) {
    const config = mainConfig(ctx.configs);
    if (!config) return h.passed('No ZeroClaw config.toml found');
    const gw = asRecord(config.data.gateway) ?? {};
    const evidence: Evidence[] = findings(gw).map(f => ({
      file: config.filePath,
      ...tomlLine(config.raw, 'gateway', f.key),
      detail: f.detail,
    }));
    return h.fromEvidence(evidence, {
      passed: 'Gateway safeguards are at their defaults',
      failed: (n) => `${n} gateway safeguard(s) relaxed`,
      fixable: true,
      fixDescription:
        'Set allow_self_upgrade / trust_forwarded_headers / allow_remote_admin = false (unless behind a trusted proxy) and restore pair_rate_limit_per_minute = 10, webhook_rate_limit_per_minute = 60',
    });
  },

  async fix(ctx) {
    const config = mainConfig(ctx.configs);
    const gw = asRecord(config?.data.gateway) ?? {};
    const updates = findings(gw).map(f => [`gateway.${f.key}`, f.fix] as [string, unknown]);
    return writeMainConfig(ctx, 'ZC-016', updates, 'Restored gateway safeguards to their defaults');
  },
});
