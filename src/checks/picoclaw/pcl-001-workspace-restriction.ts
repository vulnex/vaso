import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { envNote, envOverrideFor } from '../../adapters/env-overrides.js';
import { fixFirstConfig } from '../../remediation/config-writer.js';
import { asRecord, picoMainConfigs } from './shared.js';
import { configFixTargets } from '../../remediation/fix-refusal.js';

export const pcl001 = defineCheck({
  id: 'PCL-001',
  name: 'PicoClaw Workspace Restriction Disabled',
  category: 'picoclaw',
  severity: 'warning',
  description: 'agents.defaults.restrict_to_workspace: false lets file and exec tools work anywhere the user can (the default confines them to the agent workspace); allow_read_outside_workspace: true lets file reads leave it.',
  supportedAgents: ['picoclaw'],

  fixTargets: configFixTargets,

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    let restrictOff = false;
    // A value set by an env var survives any config edit: no fix to offer then
    let envSet = false;
    for (const config of picoMainConfigs(ctx.configs)) {
      const defaults = asRecord(asRecord(config.data.agents)?.defaults);
      if (!defaults) continue;
      if (defaults.restrict_to_workspace === false) {
        restrictOff = true;
        envSet ||= envOverrideFor(config.data, 'agents.defaults.restrict_to_workspace') !== undefined;
        evidence.push({
          file: config.filePath,
          snippet: `agents.defaults.restrict_to_workspace: false${envNote(config.data, 'agents.defaults.restrict_to_workspace')}`,
          detail: 'File and exec tools are not confined to the workspace — a prompt-injected turn can read or write ~/.ssh, cloud credentials and shell profiles',
        });
      } else if (defaults.allow_read_outside_workspace === true) {
        evidence.push({
          file: config.filePath,
          snippet: `agents.defaults.allow_read_outside_workspace: true${envNote(config.data, 'agents.defaults.allow_read_outside_workspace')}`,
          detail: 'File reads may leave the workspace (writes stay confined)',
        });
      }
    }
    return h.fromEvidence(evidence, {
      passed: 'PicoClaw tools are confined to the agent workspace',
      failed: () => restrictOff
        ? 'PicoClaw tools can reach files outside the agent workspace'
        : 'PicoClaw file reads can leave the agent workspace',
      fixable: restrictOff && !envSet,
      fixDescription: envSet
        ? 'Unset PICOCLAW_AGENTS_DEFAULTS_RESTRICT_TO_WORKSPACE (it overrides the config file), then set agents.defaults.restrict_to_workspace to true'
        : 'Set agents.defaults.restrict_to_workspace to true',
    });
  },

  async fix(ctx) {
    return fixFirstConfig(picoMainConfigs(ctx.configs), {
      checkId: 'PCL-001',
      path: 'agents.defaults.restrict_to_workspace',
      value: true,
      message: 'Set agents.defaults.restrict_to_workspace to true',
    });
  },
});
