import { extname } from 'node:path';
import type { ScanContext } from '../../core/types.js';
import type { FSProvider } from '../../core/fs-provider.js';
import { BINARY_EXTENSIONS, getAllSkillsDirs, getSkillFiles } from '../../core/utils.js';
import { readCappedFile } from '../../core/file-limits.js';

/** Every skills directory of the installation (not just the primary one). */
export function skillsDirsOf(ctx: ScanContext): string[] {
  return getAllSkillsDirs(ctx.installation);
}

/** The engine's skill file list, else a walk of every skills directory. */
export async function skillFilesOf(ctx: ScanContext): Promise<string[]> {
  if (ctx.skillFiles) return ctx.skillFiles;
  const lists = await Promise.all(skillsDirsOf(ctx).map(d => getSkillFiles(d, ctx.fs)));
  return [...new Set(lists.flat())];
}

function isMarkdown(file: string): boolean {
  return extname(file).toLowerCase() === '.md';
}

/** Source or script (AST-analyzable), as opposed to SKILL.md or a compiled binary. */
export function isSourceFile(file: string): boolean {
  const ext = extname(file).toLowerCase();
  return ext !== '.md' && !BINARY_EXTENSIONS.has(ext);
}

/**
 * Fenced code blocks of a Markdown file, every other line blanked so line
 * numbers still point into the file. SKILL.md is instructions: the agent runs
 * what its code blocks say (`curl … | bash` as an "install step"), while the
 * prose is SKL-007's subject.
 */
export function markdownCodeBlocks(md: string): string {
  let fence: string | undefined;
  return md.split('\n').map(line => {
    const m = /^\s{0,3}(`{3,}|~{3,})/.exec(line);
    if (m) {
      if (!fence) fence = m[1];
      else if (m[1][0] === fence[0] && m[1].length >= fence.length) fence = undefined;
      return '';
    }
    return fence ? line : '';
  }).join('\n');
}

/**
 * Text of a skill file for a check, or undefined when the check has nothing
 * to read in it:
 *  - 'code' (AST analysis): scripts and source only — not SKILL.md, not
 *    compiled binaries;
 *  - 'patterns' (regex rules): also SKILL.md, reduced to its code blocks.
 * Binary content (a NUL byte — an extensionless native `helper`) is skipped by
 * both. Throws ScanLimitError for a file over the size limit.
 */
export async function readSkillText(fs: FSProvider, file: string, mode: 'code' | 'patterns'): Promise<string | undefined> {
  if (BINARY_EXTENSIONS.has(extname(file).toLowerCase())) return undefined;
  if (mode === 'code' && !isSourceFile(file)) return undefined;
  const text = await readCappedFile(fs, file);
  if (text.includes('\0')) return undefined;
  return isMarkdown(file) ? markdownCodeBlocks(text) : text;
}
