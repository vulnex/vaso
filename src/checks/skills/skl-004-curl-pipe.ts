import { readFile } from 'node:fs/promises';
import type { CheckModule, ScanContext, CheckResult, Evidence } from '../../core/types.js';
import { scanWithPatterns, SECURITY_PATTERNS } from '../../analyzers/pattern-engine.js';
import { getSkillFiles } from '../../core/utils.js';

const CURL_PIPE_RULES = SECURITY_PATTERNS.filter(r => r.category === 'curl-pipe');

export const skl004: CheckModule = {
  id: 'SKL-004',
  name: 'Curl-Pipe Execution',
  category: 'skills',
  severity: 'critical',
  description: 'Detect curl|sh, wget|bash, and similar pipe-to-shell execution',

  async run(ctx: ScanContext): Promise<CheckResult> {
    const evidence: Evidence[] = [];
    const skillsDir = ctx.installation.skillsDir;
    if (!skillsDir) {
      return { id: 'SKL-004', name: 'Curl-Pipe Execution', category: 'skills', severity: 'critical', passed: true, message: 'No skills directory found' };
    }

    const files = ctx.skillFiles ?? await getSkillFiles(skillsDir);

    for (const file of files) {
      try {
        const code = await readFile(file, 'utf-8');
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

    return {
      id: 'SKL-004',
      name: 'Curl-Pipe Execution',
      category: 'skills',
      severity: 'critical',
      passed: evidence.length === 0,
      message: evidence.length === 0
        ? 'No curl-pipe execution patterns detected'
        : `Found ${evidence.length} curl-pipe execution pattern(s)`,
      evidence: evidence.length > 0 ? evidence : undefined,
    };
  },
};
