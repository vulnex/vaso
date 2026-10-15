import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

const WORLD_WRITABLE_PREFIXES = ['/tmp/', '/var/tmp/', '/private/tmp/', '/dev/shm/'];
const REDIRECT_VARS = ['OPENCLAW_CONFIG_PATH', 'OPENCLAW_STATE_DIR', 'OPENCLAW_HOME'];

export const oc004 = defineCheck({
  id: 'OC-004',
  name: 'OpenClaw Config Location Redirected',
  category: 'openclaw',
  severity: 'warning',
  description: 'Detect when OPENCLAW_HOME, OPENCLAW_STATE_DIR or OPENCLAW_CONFIG_PATH redirects config loading away from the user home directory, especially into world-writable locations (/tmp, /var/tmp, /dev/shm) where an attacker could plant a shadow config.',
  supportedAgents: ['openclaw'],
  supportedPlatforms: ['darwin', 'linux'],

  async run(ctx, h) {
    if (ctx.installation.agentName) {
      return h.passed('Sub-agent installation; OC-004 only runs at top-level');
    }

    // Each variable redirects where OpenClaw loads its config from: OPENCLAW_HOME
    // replaces the home dir, OPENCLAW_STATE_DIR is the state dir,
    // OPENCLAW_CONFIG_PATH the config file.
    const installDir = ctx.installation.installDir;
    const drives = (path: string) => installDir === path || installDir.startsWith(`${path}/`)
      || ctx.configs.some(c => c.filePath === path);
    const redirect = REDIRECT_VARS
      .map(name => ({ name, value: ctx.fs.getEnv(name)?.trim() }))
      .find((v): v is { name: string; value: string } => Boolean(v.value) && drives(v.value!));
    if (!redirect) {
      return h.passed('Config loading not redirected by OPENCLAW_HOME / OPENCLAW_STATE_DIR / OPENCLAW_CONFIG_PATH');
    }
    const { name, value } = redirect;

    const userHome = ctx.fs.homedir();
    const insideHome = value.startsWith(userHome + '/');
    const worldWritable = WORLD_WRITABLE_PREFIXES.some(p => value.startsWith(p));

    if (insideHome && !worldWritable) {
      return h.passed(`${name} points inside the user home (${value})`);
    }

    const detail = worldWritable
      ? `${name}=${value} points to a world-writable location — any local user can plant a shadow config`
      : `${name}=${value} points outside the user home (${userHome}) — review whether the redirect is intended`;

    const evidence: Evidence[] = [{
      file: value,
      detail,
    }];

    return h.fromEvidence(evidence, {
      passed: `${name} not set to a risky location`,
      failed: () => worldWritable
        ? `${name} redirects config loading into a world-writable directory`
        : `${name} redirects config loading outside the user home`,
      severity: worldWritable ? 'critical' : 'warning',
    });
  },
});
