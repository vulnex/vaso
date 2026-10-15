import { extname, join, relative, isAbsolute } from 'node:path';
import type { ScanContext } from '../../core/types.js';
import { getAllSkillsDirs, isExcludedPath } from '../../core/utils.js';
import { followSkillLinks } from '../../core/skill-walk.js';

// Text an indicator can hide in: code and scripts, config, and skill docs
// (SKILL.md tells the agent what to fetch and run).
const SCAN_EXTENSIONS = new Set([
  '.js', '.ts', '.mjs', '.cjs', '.jsx', '.tsx', '.mts', '.cts', '.py',
  '.sh', '.bash', '.zsh', '.ps1',
  '.json', '.jsonc', '.json5', '.yaml', '.yml', '.toml', '.env', '.ini', '.cfg', '.conf',
  '.md',
]);
// Markdown only inside skill trees: elsewhere in an install dir it is the
// agent's own data — Claude Code's per-project memory notes, plans, transcripts
// — which quote whatever the user discussed (and the probe doesn't collect).
const SKILL_ONLY_EXTENSIONS = new Set(['.md']);

export { MAX_SCAN_FILE_BYTES } from '../../core/file-limits.js';
import { readCappedFile } from '../../core/file-limits.js';

function within(path: string, dir: string): boolean {
  const rel = relative(dir, path);
  return !rel.startsWith('..') && !isAbsolute(rel);
}

/** Drop dirs nested inside another listed dir (skills under the install dir) — walk each tree once. */
function outermost(dirs: string[]): string[] {
  const unique = [...new Set(dirs)];
  return unique.filter(d => !unique.some(o => {
    if (o === d) return false;
    const rel = relative(o, d);
    return rel !== '' && !rel.startsWith('..') && !isAbsolute(rel);
  }));
}

/**
 * Code and config files an IOC check should read for an installation: the
 * install dir and skills dirs, minus vendor/VCS dirs and — outside skill
 * trees — build output (see isExcludedPath), files already covered by
 * `ctx.configs`, and oversized files.
 */
export async function iocScanFiles(ctx: ScanContext): Promise<string[]> {
  const dirs = outermost([ctx.installation.installDir, ...getAllSkillsDirs(ctx.installation)]);
  const skip = new Set(ctx.configs.map(c => c.filePath));
  const files: string[] = [];
  const skillsDirs = getAllSkillsDirs(ctx.installation);
  for (const dir of dirs) {
    let entries;
    try {
      entries = await ctx.fs.readdirEntries(dir, { recursive: true });
    } catch {
      continue;
    }
    // Skills symlinked in from outside the tree: the listing shows the link only
    for (const skills of skillsDirs) {
      const rel = relative(dir, skills);
      if (rel.startsWith('..') || isAbsolute(rel)) continue;
      entries = entries.concat(await followSkillLinks(ctx.fs, skills, entries));
    }
    for (const entry of entries) {
      const ext = extname(entry.name).toLowerCase();
      if (!entry.isFile || !SCAN_EXTENSIONS.has(ext)) continue;
      // Build output is skill code inside a skill tree, a build artefact elsewhere
      const skillsRoot = entry.parentPath ? skillsDirs.find(s => within(entry.parentPath!, s)) : undefined;
      if (!skillsRoot && SKILL_ONLY_EXTENSIONS.has(ext)) continue;
      if (skillsRoot ? isExcludedPath(skillsRoot, entry.parentPath, { keepBuildOutput: true }) || isExcludedPath(dir, skillsRoot)
        : isExcludedPath(dir, entry.parentPath)) continue;
      const fullPath = entry.parentPath ? join(entry.parentPath, entry.name) : join(dir, entry.name);
      if (skip.has(fullPath)) continue;
      skip.add(fullPath);
      files.push(fullPath);
    }
  }
  return files;
}

/** File content, or undefined when unreadable or larger than MAX_SCAN_FILE_BYTES. */
export async function readScanFile(ctx: ScanContext, file: string): Promise<string | undefined> {
  try {
    return await readCappedFile(ctx.fs, file);
  } catch {
    return undefined;
  }
}
