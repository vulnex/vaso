import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

const WORLD_WRITABLE_PREFIXES = ['/tmp/', '/var/tmp/', '/private/tmp/', '/dev/shm/'];

export const oc004 = defineCheck({
  id: 'OC-004',
  name: 'OPENCLAW_HOME Redirects Config Loading',
  category: 'openclaw',
  severity: 'warning',
  description: 'Detect when the OPENCLAW_HOME environment variable redirects config loading away from the user home directory, especially into world-writable locations (/tmp, /var/tmp, /dev/shm) where an attacker could plant a shadow config.',
  supportedAgents: ['openclaw'],
  supportedPlatforms: ['darwin', 'linux'],

  async run(ctx, h) {
    if (ctx.installation.agentName) {
      return h.passed('Sub-agent installation; OC-004 only runs at top-level');
    }

    const envHome = process.env.OPENCLAW_HOME;
    if (!envHome) {
      return h.passed('OPENCLAW_HOME not set');
    }

    if (ctx.installation.installDir !== envHome) {
      return h.passed('Installation not driven by OPENCLAW_HOME');
    }

    const userHome = ctx.fs.homedir();
    const insideHome = envHome.startsWith(userHome + '/');
    const worldWritable = WORLD_WRITABLE_PREFIXES.some(p => envHome.startsWith(p));

    if (insideHome && !worldWritable) {
      return h.passed(`OPENCLAW_HOME points inside the user home (${envHome})`);
    }

    const detail = worldWritable
      ? `OPENCLAW_HOME=${envHome} points to a world-writable location — any local user can plant a shadow config`
      : `OPENCLAW_HOME=${envHome} points outside the user home (${userHome}) — review whether the redirect is intended`;

    const evidence: Evidence[] = [{
      file: envHome,
      detail,
    }];

    return h.fromEvidence(evidence, {
      passed: 'OPENCLAW_HOME not set to a risky location',
      failed: () => worldWritable
        ? 'OPENCLAW_HOME redirects config loading into a world-writable directory'
        : 'OPENCLAW_HOME redirects config loading outside the user home',
      severity: worldWritable ? 'critical' : 'warning',
    });
  },
});
