import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { analyzeCode } from '../../analyzers/ast-analyzer.js';
import { getSkillFiles } from '../../core/utils.js';

export const skl003 = defineCheck({
  id: 'SKL-003',
  name: 'Eval/Exec Usage',
  category: 'skills',
  severity: 'critical',
  description: 'Detect eval(), new Function(), exec(), and other dynamic code execution',

  async run(ctx, h) {
    const skillsDir = ctx.installation.skillsDir;
    if (!skillsDir) return h.passed('No skills directory found');

    const evidence: Evidence[] = [];
    const files = ctx.skillFiles ?? await getSkillFiles(skillsDir, ctx.fs);

    for (const file of files) {
      try {
        const code = await ctx.fs.readFile(file);
        const flows = analyzeCode(code, file);
        const execFlows = flows.filter(f => f.type === 'eval-exec');

        for (const flow of execFlows) {
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
      passed: 'No eval/exec usage detected',
      failed: (n) => `Found ${n} dynamic code execution call(s)`,
    });
  },
});
