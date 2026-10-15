import { join, extname } from 'node:path';
import type { Evidence, ScanContext } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { scanWithPatterns, SECURITY_PATTERNS } from '../../analyzers/pattern-engine.js';
import { markTestCode } from '../../analyzers/test-paths.js';
import { getAllSkillsDirs, isExcludedPath } from '../../core/utils.js';
import { readCappedFile } from '../../core/file-limits.js';
import { walkSkillTree } from '../../core/skill-walk.js';

const DOC_EXTENSIONS = new Set(['.md', '.txt', '.rst']);
const PROMPT_INJECTION_RULES = SECURITY_PATTERNS.filter(r => r.category === 'prompt-injection');

async function getDocFiles(dir: string, fs: ScanContext['fs']): Promise<string[]> {
  const files: string[] = [];
  try {
    const entries = await walkSkillTree(fs, dir);
    for (const entry of entries) {
      // Same vendor/VCS exclusions as the code walk (node_modules READMEs aren't skill docs)
      if (entry.isFile && !isExcludedPath(dir, entry.parentPath, { keepBuildOutput: true })) {
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

export const skl007 = defineCheck({
  id: 'SKL-007',
  name: 'Prompt Injection in SKILL.md',
  category: 'skills',
  severity: 'warning',
  description: 'Detect prompt injection patterns in skill documentation files',

  async run(ctx, h) {
    const dirs = getAllSkillsDirs(ctx.installation);
    if (dirs.length === 0) return h.passed('No skills directory found');

    const evidence: Evidence[] = [];
    const files = [...new Set((await Promise.all(dirs.map(d => getDocFiles(d, ctx.fs)))).flat())];

    for (const file of files) {
      try {
        const content = await readCappedFile(ctx.fs, file);
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

    await markTestCode(evidence, ctx.installation, ctx.fs);
    return h.fromEvidence(evidence, {
      passed: 'No prompt injection patterns found in skill docs',
      failed: (n) => `Found ${n} prompt injection pattern(s) in skill documentation`,
    });
  },
});
