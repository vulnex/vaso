import { readFile } from 'node:fs/promises';
import type { CheckModule, ScanContext, CheckResult, Evidence } from '../../core/types.js';
import { analyzeCode } from '../../analyzers/ast-analyzer.js';
import { getSkillFiles } from '../../core/utils.js';

export const skl010: CheckModule = {
  id: 'SKL-010',
  name: 'Unauthorized FS Access',
  category: 'skills',
  severity: 'warning',
  description: 'Detect file operations accessing paths outside the workspace',

  async run(ctx: ScanContext): Promise<CheckResult> {
    const evidence: Evidence[] = [];
    const skillsDir = ctx.installation.skillsDir;
    if (!skillsDir) {
      return { id: 'SKL-010', name: 'Unauthorized FS Access', category: 'skills', severity: 'warning', passed: true, message: 'No skills directory found' };
    }

    const files = ctx.skillFiles ?? await getSkillFiles(skillsDir);

    for (const file of files) {
      try {
        const code = await readFile(file, 'utf-8');
        const flows = analyzeCode(code, file);
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

    return {
      id: 'SKL-010',
      name: 'Unauthorized FS Access',
      category: 'skills',
      severity: 'warning',
      passed: evidence.length === 0,
      message: evidence.length === 0
        ? 'No unauthorized filesystem access detected'
        : `Found ${evidence.length} unauthorized filesystem access(es)`,
      evidence: evidence.length > 0 ? evidence : undefined,
    };
  },
};
