import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { skillFilesOf, skillsDirsOf, noSkillsDirResult } from './skill-files.js';
import { analyzeSkillSource, readSkillSource } from './skill-source.js';
import { markTestCode } from '../../analyzers/test-paths.js';

export const skl010 = defineCheck({
  id: 'SKL-010',
  name: 'Unauthorized FS Access',
  category: 'skills',
  severity: 'warning',
  description: 'Detect file operations accessing paths outside the workspace',

  async run(ctx, h) {
    const noDir = noSkillsDirResult(ctx, h);
    if (noDir) return noDir;

    const evidence: Evidence[] = [];
    const files = await skillFilesOf(ctx);

    for (const file of files) {
      try {
        const src = await readSkillSource(ctx, file, 'code');
        if (src === undefined) continue;
        // Python skill scripts go through the Python analyzer; Babel can't read them.
        const flows = analyzeSkillSource(src);
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
