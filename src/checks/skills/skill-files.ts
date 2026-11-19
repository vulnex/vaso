import type { CheckModule, CheckResult, Evidence, ScanContext, UnscannedSkillsDir } from '../../core/types.js';
import type { CheckHelpers } from '../../core/check-builder.js';
import { getAllSkillsDirs, getSkillFiles, listSkillTree } from '../../core/utils.js';
import { unscannedShortReason } from '../../core/skill-root-scope.js';

/** Every skills directory of the installation (not just the primary one). */
export function skillsDirsOf(ctx: ScanContext): string[] {
  return getAllSkillsDirs(ctx.installation);
}

/** How many items a message lists before "… and N more" (SKL-002 evidence lists every one). */
export const MAX_LISTED_IN_MESSAGE = 20;

/**
 * `items` joined for a one-line message, the first MAX_LISTED_IN_MESSAGE
 * only: a skills directory holding thousands of links over the entry limit
 * must not turn every skill check's message into a list of all of them.
 */
export function cappedList(items: readonly string[], max = MAX_LISTED_IN_MESSAGE): string {
  if (items.length <= max) return items.join(', ');
  return `${items.slice(0, max).join(', ')} … and ${items.length - max} more`;
}

/** Why a skills directory went unscanned, in a few words. */
export function unscannedShort(u: UnscannedSkillsDir): string {
  return unscannedShortReason(u);
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
  const list = cappedList(unscanned.map(u => `${u.path} (${unscannedShort(u)})`));
  return h.passed(`Not verified — skills directory ${list} not scanned; reported by SKL-002`);
}

/**
 * A skill check whose pass says which config-set skills directories it did
 * not look at, when the installation has others it did scan: "No reverse
 * shell detected" over the scanned ones alone would read as a verdict on all
 * (with none scanned, noSkillsDirResult already says "Not verified").
 */
export function notingUnscannedRoots(check: CheckModule): CheckModule {
  const run = check.run;
  return {
    ...check,
    async run(ctx) {
      const result = await run(ctx);
      return result.passed ? { ...result, message: `${result.message}${unscannedRootsNote(ctx)}` } : result;
    },
  };
}

/**
 * The note notingUnscannedRoots appends to a pass — for a check that adds it
 * itself, only to a verdict over the skill trees (IOC-008's "skipped, no API
 * key" isn't one). '' when every config-set skills directory was scanned, or
 * none was (noSkillsDirResult says so).
 */
export function unscannedRootsNote(ctx: ScanContext): string {
  const unscanned = ctx.installation.unscannedSkillsDirs ?? [];
  if (unscanned.length === 0 || skillsDirsOf(ctx).length === 0) return '';
  const list = cappedList(unscanned.map(u => u.path));
  return ` (skills ${unscanned.length === 1 ? 'directory' : 'directories'} ${list} not scanned; see SKL-002)`;
}

/** The engine's skill file list, else a walk of every skills directory. */
export async function skillFilesOf(ctx: ScanContext): Promise<string[]> {
  if (ctx.skillFiles) return ctx.skillFiles;
  // one walk per context, however many helpers of a check ask
  let walk = walks.get(ctx);
  if (!walk) {
    walk = Promise.all(skillsDirsOf(ctx).map(d => getSkillFiles(d, ctx.fs))).then(lists => [...new Set(lists.flat())]);
    walks.set(ctx, walk);
  }
  return walk;
}

const walks = new WeakMap<ScanContext, Promise<string[]>>();

/**
 * Folders inside the skill trees that can't be listed (a chmod-000 folder in
 * a skill): the engine's walk, else a walk of every skills directory. The
 * skill directories directly under a root aren't among them (SKL-002 reports
 * those from unlistableSkillDirs).
 */
export async function skillUnlistableDirsOf(ctx: ScanContext): Promise<string[]> {
  if (ctx.skillFiles) return ctx.skillUnlistableDirs ?? [];
  const lists = await Promise.all(skillsDirsOf(ctx).map(async d => (await listSkillTree(d, ctx.fs)).unlistableNested));
  return [...new Set(lists.flat())];
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
