import { extname } from 'node:path';
import type { CheckResult, Evidence, ScanContext, UnscannedSkillsDir } from '../../core/types.js';
import type { CheckHelpers } from '../../core/check-builder.js';
import type { FSProvider } from '../../core/fs-provider.js';
import { BINARY_EXTENSIONS, getAllSkillsDirs, getSkillFiles } from '../../core/utils.js';
import { readCappedFile } from '../../core/file-limits.js';
import { binaryFileFormat, sourceText } from '../../analyzers/binary-text.js';

/** Every skills directory of the installation (not just the primary one). */
export function skillsDirsOf(ctx: ScanContext): string[] {
  return getAllSkillsDirs(ctx.installation);
}

/** Why a config-set skills directory went unscanned, in a few words. */
export function unscannedShort(reason: UnscannedSkillsDir['reason']): string {
  switch (reason) {
    case 'home': return 'the home directory itself';
    case 'outside': return 'outside the user\'s home or in a credential store';
    case 'limit': return 'over the remote probe\'s entry limit';
    case 'relative': return 'set as a relative path';
  }
}

/**
 * The early result of a skill check when the installation has no skills
 * directory to walk, undefined when it has one. A skills directory the
 * config sets but no scan walks (outside the home, …) is not "no skills
 * directory": SKL-002 reports it as not scanned (a warning), the other skill
 * checks say their verdict is not verified instead of claiming none exists.
 */
export function noSkillsDirResult(ctx: ScanContext, h: CheckHelpers, none = 'No skills directory found'): CheckResult | undefined {
  if (skillsDirsOf(ctx).length > 0) return undefined;
  const unscanned = ctx.installation.unscannedSkillsDirs ?? [];
  if (unscanned.length === 0) return h.passed(none);
  const list = unscanned.map(u => `${u.path} (${unscannedShort(u.reason)})`).join(', ');
  return h.passed(`Not verified — skills directory ${list} not scanned; reported by SKL-002`);
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
 * Binary content (an extensionless native `helper`, an archive — told by its
 * format signature; a script never is) is skipped by both: BinarySkillFile
 * is thrown, which every check skips and SKL-002 reports (unreadableSkillFile). Throws
 * ScanLimitError for a file over the size limit.
 */
export async function readSkillText(fs: FSProvider, file: string, mode: 'code' | 'patterns'): Promise<string | undefined> {
  if (BINARY_EXTENSIONS.has(extname(file).toLowerCase())) return undefined;
  if (mode === 'code' && !isSourceFile(file)) return undefined;
  const raw = await readCappedFile(fs, file);
  const format = await binaryFileFormat(fs, file, raw);
  if (format) throw new BinarySkillFile(file, format);
  const text = sourceText(raw);
  return isMarkdown(file) ? markdownCodeBlocks(text) : text;
}

/** A skill file whose content is a compiled executable or an archive, not source. */
export class BinarySkillFile extends Error {
  constructor(readonly path: string, readonly format: string) {
    super(`${path}: ${format}, not source`);
    this.name = 'BinarySkillFile';
  }
}

/**
 * Evidence for a skill file the scan can't read (EACCES/EPERM — locally, or
 * a file the remote probe was denied), or that is binary, undefined for any
 * other error. Every content check skips such a file;
 * SKL-002 reports it so it isn't passed as reviewed.
 */
export function unreadableSkillFile(file: string, err: unknown): Evidence | undefined {
  if (err instanceof BinarySkillFile) {
    // not mitigated: unreviewed code the agent may run
    return { file, detail: `not scanned: ${err.format} (compiled or packed content can't be analysed)` };
  }
  const code = (err as NodeJS.ErrnoException | null)?.code;
  if (code !== 'EACCES' && code !== 'EPERM') return undefined;
  return {
    file,
    detail: 'Skill file can\'t be read — hidden from review and from these checks (an agent running with more privileges than this scan still loads it)',
  };
}
