import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { fixFirstConfig } from '../../remediation/config-writer.js';
import { asRecord, getPath, nanobotConfigs, pyBool } from './shared.js';
import { configFixTargets } from '../../remediation/fix-refusal.js';

export const nb003 = defineCheck({
  id: 'NB-003',
  name: 'Workspace Restriction Disabled',
  category: 'nanobot',
  severity: 'warning',
  description: 'Check tools.restrictToWorkspace (default false). When off, the file tools (read/write/edit/list) and shell exec path guards accept any path the user can reach — ~/.ssh, ~/.aws, other projects, and nanobot\'s own config.json with its API keys.',
  supportedAgents: ['nanobot'],

  fixTargets: configFixTargets,

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    for (const config of nanobotConfigs(ctx.configs)) {
      const tools = asRecord(config.data.tools);
      // Current key, then the legacy tools.exec.restrictToWorkspace that the
      // loader migrates when the current key is absent.
      const current = getPath(config.data, 'tools.restrictToWorkspace');
      const restrict = current ?? getPath(tools, 'exec.restrictToWorkspace');
      if (pyBool(restrict) === true) continue;
      evidence.push({
        file: config.filePath,
        snippet: `tools.restrictToWorkspace: ${restrict === undefined ? '(unset, defaults to false)' : JSON.stringify(restrict)}`,
        detail: 'File and shell tools may access paths outside the agent workspace',
      });
    }
    return h.fromEvidence(evidence, {
      passed: 'tools.restrictToWorkspace is enabled',
      failed: () => 'Workspace restriction is disabled — agent tools can reach files outside the workspace',
      fixable: evidence.length > 0,
      fixDescription: 'Set "tools": { "restrictToWorkspace": true } in ~/.nanobot/config.json',
    });
  },

  async fix(ctx) {
    return fixFirstConfig(nanobotConfigs(ctx.configs), {
      checkId: 'NB-003',
      path: 'tools.restrictToWorkspace',
      value: true,
      message: 'Set tools.restrictToWorkspace=true',
      noConfigMessage: 'No nanobot config.json found',
    });
  },
});
