import type { Evidence } from '../../core/types.js';
import { basename, dirname, join } from 'node:path';
import { defineCheck } from '../../core/check-builder.js';

const LEGACY_DIR_NAMES = new Set(['.clawdbot', '.moltbot']);

export const oc003 = defineCheck({
  id: 'OC-003',
  name: 'Legacy Bot Config Directory',
  category: 'openclaw',
  severity: 'warning',
  description: 'Detect legacy `.clawdbot` / `.moltbot` config directories. The OpenClaw adapter still loads these alongside `.openclaw`, so stale or weaker configs left over from migrations remain active.',
  supportedAgents: ['openclaw'],

  async run(ctx, h) {
    const installation = ctx.installation;
    if (installation.agentName) {
      return h.passed('Sub-agent installation; OC-003 only runs at top-level');
    }

    const installDir = installation.installDir;
    const dirName = basename(installDir);
    if (!LEGACY_DIR_NAMES.has(dirName)) {
      return h.passed('Not a legacy bot directory');
    }

    const parent = dirname(installDir);
    const openclawDir = join(parent, '.openclaw');
    const openclawExists = await ctx.fs.access(openclawDir);

    const detail = openclawExists
      ? `Legacy ${dirName} directory exists alongside .openclaw — config is still loaded by the adapter (sibling/migration leftover)`
      : `Legacy ${dirName} directory in use without a current .openclaw counterpart — verify intended`;

    const evidence: Evidence[] = [{
      file: installDir,
      detail,
    }];

    return h.fromEvidence(evidence, {
      passed: 'No legacy bot directories detected',
      failed: () => `Legacy bot directory ${dirName} loaded by adapter`,
    });
  },
});
