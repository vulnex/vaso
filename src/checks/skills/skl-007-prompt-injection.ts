import { join, extname } from 'node:path';
import type { CheckModule, ScanContext, CheckResult, Evidence } from '../../core/types.js';
import { scanWithPatterns, SECURITY_PATTERNS } from '../../analyzers/pattern-engine.js';

const DOC_EXTENSIONS = new Set(['.md', '.txt', '.rst']);
const PROMPT_INJECTION_RULES = SECURITY_PATTERNS.filter(r => r.category === 'prompt-injection');

async function getDocFiles(dir: string, fs: ScanContext['fs']): Promise<string[]> {
  const files: string[] = [];
  try {
    const entries = await fs.readdirEntries(dir, { recursive: true });
    for (const entry of entries) {
      if (entry.isFile) {
        const ext = extname(entry.name);
        const name = entry.name.toUpperCase();
        if (DOC_EXTENSIONS.has(ext) || name === 'SKILL.MD' || name === 'README.MD') {
          const fullPath = entry.parentPath ? join(entry.parentPath, entry.name) : join(dir, entry.name);
          files.push(fullPath);
        }
      }
    }
  } catch {}
  return files;
}

export const skl007: CheckModule = {
  id: 'SKL-007',
  name: 'Prompt Injection in SKILL.md',
  category: 'skills',
  severity: 'warning',
  description: 'Detect prompt injection patterns in skill documentation files',

  async run(ctx: ScanContext): Promise<CheckResult> {
    const evidence: Evidence[] = [];
    const skillsDir = ctx.installation.skillsDir;
    if (!skillsDir) {
      return { id: 'SKL-007', name: 'Prompt Injection in SKILL.md', category: 'skills', severity: 'warning', passed: true, message: 'No skills directory found' };
    }

    const files = await getDocFiles(skillsDir, ctx.fs);

    for (const file of files) {
      try {
        const content = await ctx.fs.readFile(file);
        const matches = scanWithPatterns(content, PROMPT_INJECTION_RULES);

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
      id: 'SKL-007',
      name: 'Prompt Injection in SKILL.md',
      category: 'skills',
      severity: 'warning',
      passed: evidence.length === 0,
      message: evidence.length === 0
        ? 'No prompt injection patterns found in skill docs'
        : `Found ${evidence.length} prompt injection pattern(s) in skill documentation`,
      evidence: evidence.length > 0 ? evidence : undefined,
    };
  },
};
