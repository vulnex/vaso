import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

export const cur010 = defineCheck({
  id: 'CUR-010',
  name: 'Cursor Attributes Commits/PRs to Agent',
  category: 'coding-agent',
  severity: 'info',
  description: 'Surface when attribution.attributeCommitsToAgent or attributePRsToAgent is enabled',
  supportedAgents: ['cursor-cli'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      const attr = config.data.attribution as Record<string, unknown> | undefined;
      if (!attr || typeof attr !== 'object') continue;
      if (attr.attributeCommitsToAgent === true) {
        evidence.push({
          file: config.filePath,
          snippet: 'attribution.attributeCommitsToAgent = true',
          detail: 'Cursor adds an "agent" co-author/trailer to commits — visible in git history and audit logs',
        });
      }
      if (attr.attributePRsToAgent === true) {
        evidence.push({
          file: config.filePath,
          snippet: 'attribution.attributePRsToAgent = true',
          detail: 'Cursor marks PR descriptions as agent-authored',
        });
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'Cursor commit/PR attribution is not configured to mark agent authorship',
      failed: (n) => `Cursor attribution flags enabled (${n}) — agent authorship will be recorded`,
      fixDescription: 'Decide whether agent attribution is required by your audit policy; toggle attribution.* in ~/.cursor/cli-config.json',
    });
  },
});
