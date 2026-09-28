import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { getNestedValue } from '../../core/utils.js';
import { fixFirstConfig } from '../../remediation/config-writer.js';
import { atomicConfigs } from './shared.js';

export const at002 = defineCheck({
  id: 'AT-002',
  name: 'Atomic Agent Unrestricted Read Scope',
  category: 'atomic-agent',
  severity: 'warning',
  description: 'agent.readScope set to "unrestricted" — file reads anywhere on disk (~/.ssh, ~/.aws, other agents\' credentials) skip the approval gate instead of being confined to the working directory.',
  supportedAgents: ['atomic-agent'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    for (const config of atomicConfigs(ctx.configs)) {
      const scope = getNestedValue(config.data, 'agent.readScope');
      if (scope !== 'unrestricted') continue;
      evidence.push({
        file: config.filePath,
        snippet: 'agent.readScope: "unrestricted"',
        detail: 'Reads outside the working directory are not approval-gated — a prompt-injected turn can read credentials anywhere the user can',
      });
    }
    return h.fromEvidence(evidence, {
      passed: 'Atomic Agent file reads are confined to the working directory',
      failed: () => 'Atomic Agent can read any file on disk without approval',
      fixable: true,
      fixDescription: 'Set agent.readScope to "working-dir"',
    });
  },

  async fix(ctx) {
    return fixFirstConfig(atomicConfigs(ctx.configs), {
      checkId: 'AT-002',
      path: 'agent.readScope',
      value: 'working-dir',
      message: 'Set agent.readScope to "working-dir"',
    });
  },
});
