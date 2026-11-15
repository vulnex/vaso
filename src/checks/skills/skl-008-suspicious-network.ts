import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { analyzeCode } from '../../analyzers/ast-analyzer.js';
import { readSkillText, skillFilesOf, skillsDirsOf, noSkillsDirResult } from './skill-files.js';
import { markTestCode } from '../../analyzers/test-paths.js';

export const skl008 = defineCheck({
  id: 'SKL-008',
  name: 'Suspicious Network Calls',
  category: 'skills',
  severity: 'warning',
  description: 'Detect non-localhost, non-HTTPS network calls',

  async run(ctx, h) {
    const noDir = noSkillsDirResult(ctx, h);
    if (noDir) return noDir;

    const evidence: Evidence[] = [];
    const files = await skillFilesOf(ctx);

    for (const file of files) {
      try {
        const code = await readSkillText(ctx.fs, file, 'code');
        if (code === undefined) continue;
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

    await markTestCode(evidence, ctx.installation, ctx.fs);
    return h.fromEvidence(evidence, {
      passed: 'No suspicious network calls detected',
      failed: (n) => `Found ${n} suspicious network call(s)`,
    });
  },
});
