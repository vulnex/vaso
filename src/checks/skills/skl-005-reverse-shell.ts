import type { CheckModule, ScanContext, CheckResult, Evidence } from '../../core/types.js';
import { scanWithPatterns, SECURITY_PATTERNS } from '../../analyzers/pattern-engine.js';
import { getSkillFiles } from '../../core/utils.js';

const REVERSE_SHELL_RULES = SECURITY_PATTERNS.filter(r => r.category === 'reverse-shell');

export const skl005: CheckModule = {
  id: 'SKL-005',
  name: 'Reverse Shell Patterns',
  category: 'skills',
  severity: 'critical',
  description: 'Detect reverse shell patterns (Bash, netcat, Node.js, Python, etc.)',

  async run(ctx: ScanContext): Promise<CheckResult> {
    const evidence: Evidence[] = [];
    const skillsDir = ctx.installation.skillsDir;
    if (!skillsDir) {
      return { id: 'SKL-005', name: 'Reverse Shell Patterns', category: 'skills', severity: 'critical', passed: true, message: 'No skills directory found' };
    }

    const files = ctx.skillFiles ?? await getSkillFiles(skillsDir);

    for (const file of files) {
      try {
        const code = await ctx.fs.readFile(file);
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

    return {
      id: 'SKL-005',
      name: 'Reverse Shell Patterns',
      category: 'skills',
      severity: 'critical',
      passed: evidence.length === 0,
      message: evidence.length === 0
        ? 'No reverse shell patterns detected'
        : `Found ${evidence.length} reverse shell pattern(s)`,
      evidence: evidence.length > 0 ? evidence : undefined,
    };
  },
};
