import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { scanWithPatterns, SECURITY_PATTERNS } from '../../analyzers/pattern-engine.js';
import { readSkillText, skillFilesOf, skillsDirsOf } from './skill-files.js';
import { markTestCode } from '../../analyzers/test-paths.js';

const CURL_PIPE_RULES = SECURITY_PATTERNS.filter(r => r.category === 'curl-pipe');

export const skl004 = defineCheck({
  id: 'SKL-004',
  name: 'Curl-Pipe Execution',
  category: 'skills',
  severity: 'critical',
  description: 'Detect curl|sh, wget|bash, and similar pipe-to-shell execution',

  async run(ctx, h) {
    if (skillsDirsOf(ctx).length === 0) return h.passed('No skills directory found');

    const evidence: Evidence[] = [];
    const files = await skillFilesOf(ctx);

    for (const file of files) {
      try {
        const code = await readSkillText(ctx.fs, file, 'patterns');
        if (code === undefined) continue;
        const matches = scanWithPatterns(code, CURL_PIPE_RULES);

        for (const match of matches) {
          evidence.push({
            file,
            line: match.line,
            snippet: match.snippet,
            detail: match.description,
          });
        }
      } catch {}
    }

    await markTestCode(evidence, ctx.installation, ctx.fs);
    return h.fromEvidence(evidence, {
      passed: 'No curl-pipe execution patterns detected',
      failed: (n) => `Found ${n} curl-pipe execution pattern(s)`,
    });
  },
});
