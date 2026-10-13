import { extname, join, relative, isAbsolute } from 'node:path';
import type { ScanContext } from '../../core/types.js';
import { getAllSkillsDirs, isExcludedPath } from '../../core/utils.js';
import { followSkillLinks } from '../../core/skill-walk.js';

const SCAN_EXTENSIONS = new Set(['.js', '.ts', '.mjs', '.cjs', '.json', '.yaml', '.yml', '.env', '.sh']);

export { MAX_SCAN_FILE_BYTES } from '../../core/file-limits.js';
import { MAX_SCAN_FILE_BYTES } from '../../core/file-limits.js';

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
 * install dir and skills dirs, minus vendor/build/VCS dirs (the same set the
 * skill walk and the remote probe skip), files already covered by
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
      if (!entry.isFile || !SCAN_EXTENSIONS.has(extname(entry.name))) continue;
      if (isExcludedPath(dir, entry.parentPath)) continue;
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
    const content = await ctx.fs.readFile(file);
    return Buffer.byteLength(content, 'utf-8') > MAX_SCAN_FILE_BYTES ? undefined : content;
  } catch {
    return undefined;
  }
}
