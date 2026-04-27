import type { Evidence, ParsedConfig } from '../../core/types.js';
import { basename, dirname, join } from 'node:path';
import { defineCheck } from '../../core/check-builder.js';
import { loadConfig } from '../../core/config-loader.js';
import { extractPosture, findDowngrades, mergeConfigData } from './posture.js';

const CONFIG_FILENAMES = [
  'openclaw.json',
  'config.yaml',
  'config.json',
  'gateway.yaml',
  '.env',
];

export const oc005 = defineCheck({
  id: 'OC-005',
  name: 'Profile Config Weaker Than Default',
  category: 'openclaw',
  severity: 'warning',
  description: 'Detect when an `.openclaw-${profile}` config relaxes the security posture relative to the default `.openclaw` config (TLS off, gateway re-bound publicly, sandbox off, auth weakened, approval skipped).',
  supportedAgents: ['openclaw'],

  async run(ctx, h) {
    const installation = ctx.installation;
    if (installation.agentName) {
      return h.passed('Sub-agent installation; OC-005 only runs at top-level');
    }
    if (!installation.profile) {
      return h.passed('No OpenClaw profile in use');
    }

    const profileDir = installation.installDir;
    const profileDirName = basename(profileDir);
    const expectedSuffix = `.openclaw-${installation.profile}`;
    if (profileDirName !== expectedSuffix) {
      return h.passed('Installation directory does not match the active profile');
    }

    const defaultDir = join(dirname(profileDir), '.openclaw');
    if (!(await ctx.fs.access(defaultDir))) {
      return h.passed('No default .openclaw directory to compare against');
    }

    const defaultConfigs: ParsedConfig[] = [];
    for (const filename of CONFIG_FILENAMES) {
      const filePath = join(defaultDir, filename);
      try {
        defaultConfigs.push(await loadConfig(filePath, ctx.fs));
      } catch {
        // File missing or unparseable — skip.
      }
    }

    if (defaultConfigs.length === 0) {
      return h.passed('Default .openclaw directory has no readable configs');
    }

    const basePosture = extractPosture(mergeConfigData(defaultConfigs));
    const overridePosture = extractPosture(mergeConfigData(ctx.configs));
    const issues = findDowngrades(basePosture, overridePosture);

    const evidence: Evidence[] = issues.map(detail => ({
      file: profileDir,
      detail: `Profile "${installation.profile}": ${detail}`,
    }));

    return h.fromEvidence(evidence, {
      passed: `Profile "${installation.profile}" matches default security posture`,
      failed: (n) => `Profile "${installation.profile}" weakens ${n} default security setting${n === 1 ? '' : 's'}`,
    });
  },
});
