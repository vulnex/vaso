import type { Evidence } from '../../core/types.js';
import { join } from 'node:path';
import { defineCheck } from '../../core/check-builder.js';
import { queryPermissions, writableByOthers } from '../../core/permissions.js';

const SYSTEM_DIR = '/etc/openclaw';
const CONFIG_FILENAMES = [
  'openclaw.json',
  'config.yaml',
  'config.json',
  'gateway.yaml',
  '.env',
];

export const oc007 = defineCheck({
  id: 'OC-007',
  name: '/etc/openclaw Writable by Non-Root',
  category: 'openclaw',
  severity: 'critical',
  description: 'Verify the system-wide /etc/openclaw directory and its config files are not group- or world-writable. A writable system config lets any local user hijack the agent.',
  supportedAgents: ['openclaw'],
  supportedPlatforms: ['darwin', 'linux'],

  async run(ctx, h) {
    if (ctx.installation.agentName) {
      return h.passed('Sub-agent installation; OC-007 only runs at top-level');
    }

    if (!(await ctx.fs.access(SYSTEM_DIR))) {
      return h.passed('/etc/openclaw not present');
    }

    const evidence: Evidence[] = [];

    try {
      const dirPerms = await queryPermissions(ctx.fs, SYSTEM_DIR);
      if (dirPerms !== 'unsupported' && writableByOthers(dirPerms)) {
        evidence.push({
          file: SYSTEM_DIR,
          detail: `Directory permissions ${dirPerms.octal} — group or world writable (should be 755 or tighter)`,
        });
      }
    } catch {
      // Cannot stat — skip
    }

    for (const name of CONFIG_FILENAMES) {
      const filePath = join(SYSTEM_DIR, name);
      if (!(await ctx.fs.access(filePath))) continue;
      try {
        const perms = await queryPermissions(ctx.fs, filePath);
        if (perms !== 'unsupported' && writableByOthers(perms)) {
          evidence.push({
            file: filePath,
            detail: `File permissions ${perms.octal} — group or world writable`,
          });
        }
      } catch {
        // skip
      }
    }

    return h.fromEvidence(evidence, {
      passed: '/etc/openclaw and its configs are not group/world writable',
      failed: (n) => `${n} entry under /etc/openclaw ${n === 1 ? 'is' : 'are'} writable by non-root users`,
    });
  },
});
