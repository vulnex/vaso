import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { analyzeCode } from '../../analyzers/ast-analyzer.js';
import { getSkillFiles } from '../../core/utils.js';

export const skl008 = defineCheck({
  id: 'SKL-008',
  name: 'Suspicious Network Calls',
  category: 'skills',
  severity: 'warning',
  description: 'Detect non-localhost, non-HTTPS network calls',

  async run(ctx, h) {
    const skillsDir = ctx.installation.skillsDir;
    if (!skillsDir) return h.passed('No skills directory found');

    const evidence: Evidence[] = [];
    const files = ctx.skillFiles ?? await getSkillFiles(skillsDir, ctx.fs);

    for (const file of files) {
      try {
        const code = await ctx.fs.readFile(file);
        const flows = analyzeCode(code, file);
        const suspicious = flows.filter(f => f.type === 'suspicious-network');

        for (const flow of suspicious) {
          evidence.push({
            file,
            line: flow.line,
            snippet: flow.snippet,
            detail: flow.description,
          });
        }
      } catch {}
    }

    return h.fromEvidence(evidence, {
      passed: 'No suspicious network calls detected',
      failed: (n) => `Found ${n} suspicious network call(s)`,
    });
  },
});
