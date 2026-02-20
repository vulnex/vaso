import { readFile, readdir } from 'node:fs/promises';
import { join, extname } from 'node:path';
import type { CheckModule, ScanContext, CheckResult, Evidence } from '../../core/types.js';
import { scanWithPatterns, SECURITY_PATTERNS } from '../../analyzers/pattern-engine.js';

const CODE_EXTENSIONS = new Set(['.js', '.ts', '.mjs', '.cjs', '.mts', '.cts', '.sh', '.bash', '.py']);
const REVERSE_SHELL_RULES = SECURITY_PATTERNS.filter(r => r.category === 'reverse-shell');

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
        const code = await readFile(file, 'utf-8');
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
