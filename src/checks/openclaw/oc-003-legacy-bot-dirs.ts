import type { Evidence } from '../../core/types.js';
import { basename, dirname, join } from 'node:path';
import { defineCheck } from '../../core/check-builder.js';
import { LEGACY_STATE_DIRS, openclawEnvPaths } from '../../adapters/openclaw.js';

/**
 * Pre-rename state dirs, as OpenClaw 2026.9.4 treats them (`openclaw config
 * file`): ~/.clawdbot is the live state dir only while ~/.openclaw has no
 * config (then the adapter scans it as the installation); ~/.moltbot is never
 * read. Any other copy is a migration leftover — not loaded, but it may still
 * hold old tokens and keys.
 */
export const oc003 = defineCheck({
  id: 'OC-003',
  name: 'Legacy Bot Config Directory',
  category: 'openclaw',
  severity: 'warning',
  description: 'Detect pre-rename `.clawdbot` / `.moltbot` state directories. OpenClaw runs from `~/.clawdbot` only while `~/.openclaw` has no config (migrate with `openclaw doctor`); any other copy is a leftover it no longer reads, which can still hold old credentials.',
  supportedAgents: ['openclaw'],

  async run(ctx, h) {
    const installation = ctx.installation;
    if (installation.agentName || installation.profile) {
      return h.passed('Sub-agent or profile installation; OC-003 runs for the default state directory');
    }

    const installDir = installation.installDir;
    const evidence: Evidence[] = [];
    let live = false;
    if (LEGACY_STATE_DIRS.includes(basename(installDir))) {
      live = true;
      evidence.push({
        file: installDir,
        detail: `OpenClaw runs from the pre-rename ${basename(installDir)} directory (no config in .openclaw) — migrate it with \`openclaw doctor\``,
      });
    }

    // Leftovers next to the live state dir (or in the effective home when
    // OPENCLAW_STATE_DIR moved it elsewhere)
    const home = ['.openclaw', ...LEGACY_STATE_DIRS].includes(basename(installDir))
      ? dirname(installDir)
      : openclawEnvPaths(ctx.fs.homedir(), ctx.fs).home;
    for (const name of LEGACY_STATE_DIRS) {
      const dir = join(home, name);
      if (dir === installDir || !(await ctx.fs.access(dir))) continue;
      evidence.push({
        file: dir,
        detail: `Leftover ${name} directory — OpenClaw no longer reads it${name === '.moltbot' ? '' : ' while .openclaw has a config'}; remove it once nothing in it is needed (old tokens and keys may remain)`,
      });
    }

    return h.fromEvidence(evidence, {
      passed: 'No legacy bot directories detected',
      failed: (n) => live
        ? `OpenClaw runs from a pre-rename state directory`
        : `${n} leftover pre-rename state director${n === 1 ? 'y' : 'ies'} (not loaded)`,
      // A leftover is stale data, not live configuration
      severity: live ? 'warning' : 'info',
    });
  },
});
