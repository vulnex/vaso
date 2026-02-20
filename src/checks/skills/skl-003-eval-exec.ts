import { readFile, readdir } from 'node:fs/promises';
import { join, extname } from 'node:path';
import type { CheckModule, ScanContext, CheckResult, Evidence } from '../../core/types.js';
import { analyzeCode } from '../../analyzers/ast-analyzer.js';

const CODE_EXTENSIONS = new Set(['.js', '.ts', '.mjs', '.cjs', '.mts', '.cts']);

async function getSkillFiles(dir: string): Promise<string[]> {
  const files: string[] = [];
  try {
    const entries = await readdir(dir, { withFileTypes: true, recursive: true });
    for (const entry of entries) {
      if (entry.isFile() && CODE_EXTENSIONS.has(extname(entry.name))) {
        const fullPath = entry.parentPath ? join(entry.parentPath, entry.name) : join(dir, entry.name);
        files.push(fullPath);
      }
    }
  } catch {}
  return files;
}

export const skl003: CheckModule = {
  id: 'SKL-003',
  name: 'Eval/Exec Usage',
  category: 'skills',
  severity: 'critical',
  description: 'Detect eval(), new Function(), exec(), and other dynamic code execution',

  async run(ctx: ScanContext): Promise<CheckResult> {
    const evidence: Evidence[] = [];
    const skillsDir = ctx.installation.skillsDir;
    if (!skillsDir) {
      return { id: 'SKL-003', name: 'Eval/Exec Usage', category: 'skills', severity: 'critical', passed: true, message: 'No skills directory found' };
    }

    const files = ctx.skillFiles ?? await getSkillFiles(skillsDir);

    for (const file of files) {
      try {
        const code = await readFile(file, 'utf-8');
        const flows = analyzeCode(code, file);
        const execFlows = flows.filter(f => f.type === 'eval-exec');

        for (const flow of execFlows) {
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
      id: 'SKL-003',
      name: 'Eval/Exec Usage',
      category: 'skills',
      severity: 'critical',
      passed: evidence.length === 0,
      message: evidence.length === 0
        ? 'No eval/exec usage detected'
        : `Found ${evidence.length} dynamic code execution call(s)`,
      evidence: evidence.length > 0 ? evidence : undefined,
    };
  },
};
