import { extname, join } from 'node:path';
import type { ScanContext } from '../../core/types.js';
import { readCappedFile } from '../../core/file-limits.js';
import { claudePlugins } from '../../adapters/claude-plugins.js';
import { loadForm, loadTimeCommands } from '../skills/skill-source.js';

/** At most this many custom command files are read per installation. */
const MAX_COMMAND_FILES = 2000;

/** A shell command a custom slash command runs when it is invoked. */
export interface CustomCommandRun {
  file: string;
  line: number;
  command: string;
  /** How it is written: `!`…`` or ```! block. */
  form: string;
}

/**
 * Directories of custom slash commands (`<name>.md`, subfolders too) for an
 * installation: `commands/` under its directory (~/.claude/commands for the
 * user install, <repo>/.claude/commands for a project) and under each
 * enabled plugin's install path.
 */
async function commandDirs(ctx: ScanContext): Promise<string[]> {
  const dirs = [join(ctx.installation.installDir, 'commands')];
  for (const plugin of await claudePlugins(ctx.installation.installDir, ctx.configs, ctx.fs)) {
    if (plugin.enabled) dirs.push(join(plugin.installPath, 'commands'));
  }
  return dirs;
}

/**
 * The shell commands custom slash commands run when invoked — their
 * `` !`cmd` `` lines and ```` ```! ```` blocks, matched as Claude Code
 * matches a skill's (loadTimeCommands); `disableSkillShellExecution` covers
 * both. Unreadable files are skipped.
 */
export async function customCommandRuns(ctx: ScanContext): Promise<CustomCommandRun[]> {
  const out: CustomCommandRun[] = [];
  let read = 0;
  for (const dir of await commandDirs(ctx)) {
    let entries;
    try {
      entries = await ctx.fs.readdirEntries(dir, { recursive: true });
    } catch {
      continue;
    }
    if (!Array.isArray(entries)) continue;
    const files = entries
      .filter(e => e.isFile && extname(e.name).toLowerCase() === '.md')
      .map(e => (e.parentPath ? join(e.parentPath, e.name) : join(dir, e.name)))
      .sort();
    for (const file of files) {
      if (read++ >= MAX_COMMAND_FILES) return out;
      let text: string;
      try {
        text = await readCappedFile(ctx.fs, file);
      } catch {
        continue;
      }
      for (const run of loadTimeCommands(text)) {
        out.push({ file, line: run.line, command: run.command, form: loadForm(run.command, text, run.line) });
      }
    }
  }
  return out;
}
