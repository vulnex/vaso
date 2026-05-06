import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { analyzeCode } from '../../analyzers/ast-analyzer.js';
import { getSkillFiles } from '../../core/utils.js';

export const skl010 = defineCheck({
  id: 'SKL-010',
  name: 'Unauthorized FS Access',
  category: 'skills',
  severity: 'warning',
  description: 'Detect file operations accessing paths outside the workspace',

  async run(ctx, h) {
    const skillsDir = ctx.installation.skillsDir;
    if (!skillsDir) return h.passed('No skills directory found');

    const evidence: Evidence[] = [];
    const files = ctx.skillFiles ?? await getSkillFiles(skillsDir, ctx.fs);

    for (const file of files) {
      try {
        const code = await ctx.fs.readFile(file);
        const flows = analyzeCode(code, file);
        const fsAccess = flows.filter(f => f.type === 'fs-access');

        for (const flow of fsAccess) {
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
      passed: 'No unauthorized filesystem access detected',
      failed: (n) => `Found ${n} unauthorized filesystem access(es)`,
    });
  },
});
