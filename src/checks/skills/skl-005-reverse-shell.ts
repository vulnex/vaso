import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { scanWithPatterns, SECURITY_PATTERNS } from '../../analyzers/pattern-engine.js';
import { skillFilesOf, skillsDirsOf, noSkillsDirResult } from './skill-files.js';
import { readSkillSource } from './skill-source.js';
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
        // Every line of documentation too: a reverse shell one-liner has no
        // use in a skill's instructions
        const src = await readSkillSource(ctx, file, 'patterns', 'prose');
        if (src === undefined) continue;
        const matches = scanWithPatterns(src.text, REVERSE_SHELL_RULES);

        for (const match of matches) {
          const onLoad = src.loadCommands?.get(match.line)?.some(cmd => scanWithPatterns(cmd, REVERSE_SHELL_RULES).length > 0);
          evidence.push({
            file,
            line: match.line,
            snippet: match.snippet,
            detail: onLoad ? `${match.description} in a !\`…\` command — Claude Code runs it when it loads the skill` : match.description,
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
