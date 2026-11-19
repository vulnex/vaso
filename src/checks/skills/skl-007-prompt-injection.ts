import { join, extname } from 'node:path';
import type { Evidence, ScanContext } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { scanWithPatterns, SECURITY_PATTERNS } from '../../analyzers/pattern-engine.js';
import { markTestCode } from '../../analyzers/test-paths.js';
import { getAllSkillsDirs, isExcludedPath, unlistableSkillDirs, vendorNamedSkills } from '../../core/utils.js';
import { readCappedFile } from '../../core/file-limits.js';
import { walkSkillTree } from '../../core/skill-walk.js';
import { noSkillsDirResult } from './skill-files.js';

const DOC_EXTENSIONS = new Set(['.md', '.txt', '.rst']);
const PROMPT_INJECTION_RULES = SECURITY_PATTERNS.filter(r => r.category === 'prompt-injection');

/** `uncapped`: follow links whatever the size of their tree (`vaso skill audit`). */
async function getDocFiles(dir: string, fs: ScanContext['fs'], uncapped: boolean): Promise<string[]> {
  const files: string[] = [];
  try {
    const entries = await walkSkillTree(fs, dir, undefined, { uncapped });
    const skills = vendorNamedSkills(dir, entries);
    for (const entry of entries) {
      // Same vendor/VCS exclusions as the code walk (node_modules READMEs aren't skill docs)
      if (entry.isFile && !isExcludedPath(dir, entry.parentPath, { keepBuildOutput: true, skills })) {
        const ext = extname(entry.name);
        const name = entry.name.toUpperCase();
        if (DOC_EXTENSIONS.has(ext) || name === 'SKILL.MD' || name === 'README.MD') {
          const fullPath = entry.parentPath ? join(entry.parentPath, entry.name) : join(dir, entry.name);
          files.push(fullPath);
        }
      }
    }
  } catch {}
  // A skill dir the scan can enter but not list still has its SKILL.md
  // loaded by name (as getSkillFiles does for the code checks)
  for (const skillDir of await unlistableSkillDirs(dir, fs)) {
    const skillMd = join(skillDir, 'SKILL.md');
    if (!files.includes(skillMd) && await fs.access(skillMd)) files.push(skillMd);
  }
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
    const noDir = noSkillsDirResult(ctx, h);
    if (noDir) return noDir;

    const evidence: Evidence[] = [];
    const files = [...new Set((await Promise.all(dirs.map(d => getDocFiles(d, ctx.fs, ctx.installation.agent === 'skill-audit')))).flat())];

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
