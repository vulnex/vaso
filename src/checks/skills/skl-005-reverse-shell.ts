import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { scanWithPatterns, SECURITY_PATTERNS } from '../../analyzers/pattern-engine.js';
import { readSkillText, skillFilesOf, skillsDirsOf, noSkillsDirResult } from './skill-files.js';
import { markTestCode } from '../../analyzers/test-paths.js';

const REVERSE_SHELL_RULES = SECURITY_PATTERNS.filter(r => r.category === 'reverse-shell');

export const skl005 = defineCheck({
  id: 'SKL-005',
  name: 'Reverse Shell Patterns',
  category: 'skills',
  severity: 'critical',
  description: 'Detect reverse shell patterns (Bash, netcat, Node.js, Python, etc.)',

  async run(ctx, h) {
    const noDir = noSkillsDirResult(ctx, h);
    if (noDir) return noDir;

    const evidence: Evidence[] = [];
    const files = await skillFilesOf(ctx);

    for (const file of files) {
      try {
        const code = await readSkillText(ctx.fs, file, 'patterns');
        if (code === undefined) continue;
        const matches = scanWithPatterns(code, REVERSE_SHELL_RULES);

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
      passed: 'No reverse shell patterns detected',
      failed: (n) => `Found ${n} reverse shell pattern(s)`,
    });
  },
});
