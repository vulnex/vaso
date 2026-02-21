import { readFile } from 'node:fs/promises';
import type { CheckModule, ScanContext, CheckResult, Evidence } from '../../core/types.js';
import { analyzeCode } from '../../analyzers/ast-analyzer.js';
import { getSkillFiles } from '../../core/utils.js';

export const skl008: CheckModule = {
  id: 'SKL-008',
  name: 'Suspicious Network Calls',
  category: 'skills',
  severity: 'warning',
  description: 'Detect non-localhost, non-HTTPS network calls',

  async run(ctx: ScanContext): Promise<CheckResult> {
    const evidence: Evidence[] = [];
    const skillsDir = ctx.installation.skillsDir;
    if (!skillsDir) {
      return { id: 'SKL-008', name: 'Suspicious Network Calls', category: 'skills', severity: 'warning', passed: true, message: 'No skills directory found' };
    }

    const files = ctx.skillFiles ?? await getSkillFiles(skillsDir);

    for (const file of files) {
      try {
        const code = await readFile(file, 'utf-8');
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

    return {
      id: 'SKL-008',
      name: 'Suspicious Network Calls',
      category: 'skills',
      severity: 'warning',
      passed: evidence.length === 0,
      message: evidence.length === 0
        ? 'No suspicious network calls detected'
        : `Found ${evidence.length} suspicious network call(s)`,
      evidence: evidence.length > 0 ? evidence : undefined,
    };
  },
};
