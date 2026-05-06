import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { scanWithPatterns, SECURITY_PATTERNS } from '../../analyzers/pattern-engine.js';
import { getSkillFiles } from '../../core/utils.js';

const CURL_PIPE_RULES = SECURITY_PATTERNS.filter(r => r.category === 'curl-pipe');

export const skl004 = defineCheck({
  id: 'SKL-004',
  name: 'Curl-Pipe Execution',
  category: 'skills',
  severity: 'critical',
  description: 'Detect curl|sh, wget|bash, and similar pipe-to-shell execution',

  async run(ctx, h) {
    const skillsDir = ctx.installation.skillsDir;
    if (!skillsDir) return h.passed('No skills directory found');

    const evidence: Evidence[] = [];
    const files = ctx.skillFiles ?? await getSkillFiles(skillsDir, ctx.fs);

    for (const file of files) {
      try {
        const code = await ctx.fs.readFile(file);
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

    return h.fromEvidence(evidence, {
      passed: 'No curl-pipe execution patterns detected',
      failed: (n) => `Found ${n} curl-pipe execution pattern(s)`,
    });
  },
});
