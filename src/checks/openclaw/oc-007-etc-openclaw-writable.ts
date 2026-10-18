import { defineCheck } from '../../core/check-builder.js';

/**
 * Retired: no OpenClaw release loads anything from /etc/openclaw. Checked
 * against the published packages from clawdbot 2026.1.4 through openclaw
 * 2026.9.4 — config, .env and skills come only from the state dir
 * (~/.openclaw, $OPENCLAW_STATE_DIR, the pre-rename ~/.clawdbot); the path
 * appears only in help text and docs as an example location for files a
 * config names explicitly (a secrets provider file, TLS certificate paths).
 * A writable /etc/openclaw therefore hijacks nothing on its own. The ID
 * stays so baselines and suppressions keep resolving.
 */
export const oc007 = defineCheck({
  id: 'OC-007',
  name: '/etc/openclaw Writable by Non-Root',
  category: 'openclaw',
  severity: 'info',
  description: 'Retired: OpenClaw never reads /etc/openclaw (no release loads config, .env or skills from it), so its permissions do not affect the agent. Kept so existing baselines and suppressions resolve; always passes.',
  supportedAgents: ['openclaw'],
  supportedPlatforms: ['darwin', 'linux'],

  async run(_ctx, h) {
    return h.passed('OpenClaw does not read /etc/openclaw (no release loads config, .env or skills from it) — nothing to check');
  },
});
