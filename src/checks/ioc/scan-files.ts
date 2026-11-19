import { extname, join, relative } from 'node:path';
import type { ScanContext } from '../../core/types.js';
import { getAllSkillsDirs, isExcludedPath, relEscapes } from '../../core/utils.js';
import { skillFileInSink } from '../../core/skill-walk.js';
import { skillFilesOf } from '../skills/skill-files.js';
import { claudePlugins } from '../../adapters/claude-plugins.js';

// Text an indicator can hide in outside skill trees: code and scripts, and
// config (in skill trees every file the skill checks read counts).
const SCAN_EXTENSIONS = new Set([
  '.js', '.ts', '.mjs', '.cjs', '.jsx', '.tsx', '.mts', '.cts', '.py',
  '.sh', '.bash', '.zsh', '.ps1',
  '.json', '.jsonc', '.json5', '.yaml', '.yml', '.toml', '.env', '.ini', '.cfg', '.conf',
]);

export { MAX_SCAN_FILE_BYTES } from '../../core/file-limits.js';
import { readCappedFile } from '../../core/file-limits.js';

function within(path: string, dir: string): boolean {
  const rel = relative(dir, path);
  return !relEscapes(rel);
}

/**
 * Install paths of the Claude Code plugins the settings disable: none of
 * their files load, so — as the skill checks skip their skills — the IOC
 * checks don't read them.
 */
async function disabledPluginPaths(ctx: ScanContext): Promise<string[]> {
  if (ctx.installation.agent !== 'claude-code') return [];
  return (await claudePlugins(ctx.installation.installDir, ctx.configs, ctx.fs)).filter(p => !p.enabled).map(p => p.installPath);
}

/**
 * Files an IOC check should read for an installation:
 *  - in skill trees, every file the skill checks read (skillFilesOf: the
 *    listSkillTree walk — any extension, extensionless scripts, linked
 *    skills, vendor-folder files a skill runs or loads);
 *  - elsewhere in the install dir, code and config by extension (Markdown
 *    there is the agent's own data — Claude Code's per-project memory notes,
 *    plans, transcripts — which quote whatever the user discussed, and the
 *    probe doesn't collect), minus vendor/VCS dirs, build output
 *    (isExcludedPath) and disabled plugins;
 * never a file already covered by `ctx.configs`. Oversized files are left to
 * readScanFile.
 */
export async function iocScanFiles(ctx: ScanContext): Promise<string[]> {
  const skip = new Set(ctx.configs.map(c => c.filePath));
  const files: string[] = [];
  const skillsDirs = getAllSkillsDirs(ctx.installation);
  const realDirs = new Map<string, string>();
  for (const file of await skillFilesOf(ctx)) {
    if (skip.has(file)) continue;
    skip.add(file);
    // A credential store reached through a linked skills tree (skills →
    // ~/.claude): never read, as the probe never ships it
    const skillsRoot = skillsDirs.find(s => within(file, s));
    if (skillsRoot && await skillFileInSink(ctx.fs, skillsRoot, file, realDirs)) continue;
    files.push(file);
  }
  const dir = ctx.installation.installDir;
  let entries;
  try {
    entries = await ctx.fs.readdirEntries(dir, { recursive: true });
  } catch {
    return files;
  }
  if (!Array.isArray(entries)) return files;
  const disabled = await disabledPluginPaths(ctx);
  for (const entry of entries) {
    if (!entry.isFile || !SCAN_EXTENSIONS.has(extname(entry.name).toLowerCase())) continue;
    const parent = entry.parentPath ?? dir;
    // skill trees are read above, from the skill checks' own list
    if (skillsDirs.some(s => within(parent, s)) || isExcludedPath(dir, parent) || disabled.some(p => within(parent, p))) continue;
    const fullPath = join(parent, entry.name);
    if (skip.has(fullPath)) continue;
    skip.add(fullPath);
    files.push(fullPath);
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
