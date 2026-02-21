import { readFile } from 'node:fs/promises';
import type { CheckModule, ScanContext, CheckResult, Evidence } from '../../core/types.js';
import { analyzeCode } from '../../analyzers/ast-analyzer.js';
import { getSkillFiles } from '../../core/utils.js';

export const skl001: CheckModule = {
  id: 'SKL-001',
  name: 'Data Exfiltration Flow',
  category: 'skills',
  severity: 'critical',
  description: 'Detect data flows from file/env sources to network sinks (AST-based)',

  async run(ctx: ScanContext): Promise<CheckResult> {
    const evidence: Evidence[] = [];
    const skillsDir = ctx.installation.skillsDir;
    if (!skillsDir) {
      return { id: 'SKL-001', name: 'Data Exfiltration Flow', category: 'skills', severity: 'critical', passed: true, message: 'No skills directory found' };
    }

    const files = ctx.skillFiles ?? await getSkillFiles(skillsDir);

    for (const file of files) {
      try {
        const code = await readFile(file, 'utf-8');
        const flows = analyzeCode(code, file);
        const exfil = flows.filter(f => f.type === 'source-to-sink');

        for (const flow of exfil) {
          evidence.push({
            file,
            line: flow.line,
            snippet: flow.snippet,
            detail: flow.description,
          });
        }
      } catch {
        // Skip unreadable files
      }
    }

    return {
      id: 'SKL-001',
      name: 'Data Exfiltration Flow',
      category: 'skills',
      severity: 'critical',
      passed: evidence.length === 0,
      message: evidence.length === 0
        ? 'No data exfiltration flows detected'
        : `Found ${evidence.length} data exfiltration flow(s) — data flowing from sources to network sinks`,
      evidence: evidence.length > 0 ? evidence : undefined,
    };
  },
};
