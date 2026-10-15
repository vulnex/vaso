import { extname } from 'node:path';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { analyzeCode } from '../../analyzers/ast-analyzer.js';
import { analyzePythonDataFlow } from '../../analyzers/python-sinks.js';
import { readSkillText, skillFilesOf, skillsDirsOf } from './skill-files.js';
import { markTestCode } from '../../analyzers/test-paths.js';

export const skl010 = defineCheck({
  id: 'SKL-010',
  name: 'Unauthorized FS Access',
  category: 'skills',
  severity: 'warning',
  description: 'Detect file operations accessing paths outside the workspace',

  async run(ctx, h) {
    if (skillsDirsOf(ctx).length === 0) return h.passed('No skills directory found');

    const evidence: Evidence[] = [];
    const files = await skillFilesOf(ctx);

    for (const file of files) {
      try {
        const code = await readSkillText(ctx.fs, file, 'code');
        if (code === undefined) continue;
        // Python skill scripts go through the Python analyzer; Babel can't read them.
        const flows = extname(file).toLowerCase() === '.py' ? analyzePythonDataFlow(code) : analyzeCode(code, file);
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

    await markTestCode(evidence, ctx.installation, ctx.fs);
    return h.fromEvidence(evidence, {
      passed: 'No unauthorized filesystem access detected',
      failed: (n) => `Found ${n} unauthorized filesystem access(es)`,
    });
  },
});
