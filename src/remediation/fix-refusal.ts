import { basename, dirname, isAbsolute, join } from 'node:path';
import type { CheckModule, CheckResult, FixTargets, ScanContext } from '../core/types.js';
import type { FSProvider } from '../core/fs-provider.js';
import { getUserHomeDirs } from '../adapters/openclaw.js';
import { sinkReachedThroughLink, withinRoot } from './safe-file.js';

/**
 * What `vaso fix` refuses to change, judged ahead of the fix. The write-time
 * guards in safe-file.ts are the enforcement (on open handles, so a swap
 * between check and use doesn't get around them); this is the same rule set
 * read through an FSProvider, so a scan doesn't offer a fix that would be
 * refused every time — and a second `vaso fix` doesn't fail forever on it.
 *
 * A fix changes only:
 *  - a regular file or directory (never a symlink — the link's target could
 *    be any file the user can write — nor a FIFO or device);
 *  - with a single hard link (the change would reach every name);
 *  - whose directory resolves inside the home of the installation's user,
 *    where its backup can restore it (outside it: refused);
 *  - that a link above it doesn't take into a credential store, shell
 *    startup file or /etc its own path doesn't name (`~/.copilot → ~/.aws/cop`
 *    makes ~/.copilot/session-store.db a file in ~/.aws) — a file written at
 *    its own credential path (~/.ssh/picoclaw_ed25519.key) is still fixed;
 *  - as root, owned by that home's owner.
 */

/**
 * The home a fix of the installation at `installDir` is confined to: the
 * longest user home that contains it (any user's when privileged —
 * `--all-users`), else the scanning user's home.
 */
export async function fixHomeOf(installDir: string, fs: FSProvider): Promise<string> {
  const homes = new Set<string>([fs.homedir()]);
  if (fs.isPrivileged?.()) {
    for (const { home } of await getUserHomeDirs(true, fs).catch(() => [])) homes.add(home);
  }
  let best: string | undefined;
  for (const home of homes) {
    if (withinRoot(installDir, home) && (!best || home.length > best.length)) best = home;
  }
  return best ?? fs.homedir();
}

export interface FixBoundaryInfo {
  home: string;
  /** Owner of the home; enforced only when the scan is privileged. */
  ownerUid?: number;
}

export async function fixBoundaryOf(installDir: string, fs: FSProvider): Promise<FixBoundaryInfo> {
  const home = await fixHomeOf(installDir, fs);
  // The engine takes the owner from an lstat of the home; a provider's
  // ownership follows links, so a linked home's owner is left unjudged
  const linked = await fs.readlink(home).then(() => true, () => false);
  const ownerUid = fs.isPrivileged?.() && !linked ? (await fs.ownership?.(home).catch(() => undefined))?.uid : undefined;
  return { home, ownerUid };
}

export type FixRefusalKind = 'symlink' | 'special' | 'hard-link' | 'owner' | 'outside' | 'through-link' | 'sensitive';

export interface FixRefusal {
  path: string;
  kind: FixRefusalKind;
  /** Completes "<path> …": "is a symlink", "is outside the home", … */
  reason: string;
}

/**
 * Why `vaso fix` would refuse to change `path`; `'none'` when it is not a
 * target at all (not an absolute path, missing, or not resolvable from what
 * the provider knows — a snapshot that didn't record it); undefined when the
 * fix may change it. A snapshot can't tell hard links; those are judged on
 * local scans only.
 */
export async function fixRefusal(path: string, fs: FSProvider, boundary: FixBoundaryInfo): Promise<FixRefusal | 'none' | undefined> {
  if (!isAbsolute(path)) return 'none';
  const isLink = await fs.readlink(path).then(() => true, () => false);
  if (isLink) return { path, kind: 'symlink', reason: 'is a symlink' };
  let st: Awaited<ReturnType<FSProvider['stat']>>;
  try {
    st = await fs.stat(path);
  } catch {
    return 'none';
  }
  const isDir = st.isDirectory();
  if (!st.isFile() && !isDir) return { path, kind: 'special', reason: 'is not a regular file' };
  if (!isDir && st.nlink !== undefined && st.nlink > 1) {
    return { path, kind: 'hard-link', reason: `has ${st.nlink} hard links` };
  }
  const dir = isDir ? path : dirname(path);
  const realDir = await fs.realpath(dir).catch(() => undefined);
  if (realDir === undefined) return 'none';
  if (boundary.ownerUid !== undefined && fs.isPrivileged?.()) {
    const owner = await fs.ownership?.(path).catch(() => undefined);
    if (owner && owner.uid !== boundary.ownerUid) {
      return { path, kind: 'owner', reason: `is owned by uid ${owner.uid}, not by the home's owner (uid ${boundary.ownerUid})` };
    }
  }
  const sink = sinkReachedThroughLink(path, isDir ? realDir : join(realDir, basename(path)));
  if (sink) return { path, kind: 'sensitive', reason: `is reached through a symlink into ${sink}` };
  const realHome = await fs.realpath(boundary.home).catch(() => boundary.home);
  if (withinRoot(realDir, realHome)) return undefined;
  const writtenInHome = withinRoot(dir, boundary.home) || withinRoot(dir, realHome);
  return writtenInHome
    ? { path, kind: 'through-link', reason: `is reached through a symlink (it resolves into ${realDir}, outside the home)` }
    : { path, kind: 'outside', reason: 'is outside the home' };
}

/** A permission fix (restrictFilesToOwner): it changes the modes of the files the finding lists. */
export function permissionFixTargets(_ctx: ScanContext, result: CheckResult): FixTargets {
  return { paths: evidenceFiles(result), kind: 'permissions' };
}

/**
 * A config fix (fixFirstConfig and friends): it writes only the
 * installation's config files, so of the finding's files only those count.
 * None of them listed → can't say.
 */
export function configFixTargets(ctx: ScanContext, result: CheckResult): FixTargets | undefined {
  const configs = new Set(ctx.configs.map(c => c.filePath));
  const paths = evidenceFiles(result).filter(p => configs.has(p));
  return paths.length > 0 ? { paths, kind: 'config' } : undefined;
}

function evidenceFiles(result: CheckResult): string[] {
  return [...new Set((result.evidence ?? []).flatMap(e => (e.file && isAbsolute(e.file) ? [e.file] : [])))];
}

/** Most refused paths a message names; the rest are counted. */
const MAX_NAMED = 3;

/**
 * Quote a path for a copy-paste shell command. A name with a control
 * character (a newline) is written in ANSI-C quoting (`$'a\nb'`, bash and
 * zsh) so the command shows no raw control character and copies back to the
 * same name; any other name in single quotes.
 */
export function shellQuote(path: string): string {
  if (/^[\w@%+=:,./~-]+$/.test(path)) return path;
  // eslint-disable-next-line no-control-regex
  if (!/[\x00-\x1f\x7f]/.test(path)) return `'${path.replace(/'/g, `'\\''`)}'`;
  const body = [...path].map(ch => {
    if (ch === '\\') return '\\\\';
    if (ch === "'") return "\\'";
    const code = ch.codePointAt(0)!;
    if (ch === '\n') return '\\n';
    if (ch === '\t') return '\\t';
    if (code < 0x20 || code === 0x7f) return `\\x${code.toString(16).padStart(2, '0')}`;
    return ch;
  }).join('');
  return `$'${body}'`;
}

/** `text` as a Markdown code span, its fence longer than any run of backticks inside it. */
export function codeSpan(text: string): string {
  const longest = Math.max(0, ...[...text.matchAll(/`+/g)].map(m => m[0].length));
  if (longest === 0) return `\`${text}\``;
  const fence = '`'.repeat(longest + 1);
  return `${fence} ${text} ${fence}`;
}

function describe(refused: FixRefusal[]): string {
  const named = refused.slice(0, MAX_NAMED).map(r => `${r.path} ${r.reason}`);
  if (refused.length > MAX_NAMED) named.push(`${refused.length - MAX_NAMED} more`);
  return named.join('; ');
}

/**
 * Mark a fixable result the fix would refuse: every target refused → not
 * fixable, with the reason in the message and what to do by hand in the fix
 * description; some refused → still fixable, the message names the ones the
 * fix will leave. Returns the result unchanged when nothing is refused or
 * nothing can be judged.
 */
export async function markRefusedFix(
  check: Pick<CheckModule, 'fixTargets'> | undefined,
  ctx: ScanContext,
  result: CheckResult,
  boundary: FixBoundaryInfo,
): Promise<CheckResult> {
  const targets = check?.fixTargets
    ? check.fixTargets(ctx, result)
    : { paths: evidenceFiles(result), kind: 'other' as const };
  if (!targets || targets.paths.length === 0) return result;

  const refused: FixRefusal[] = [];
  let fixable = 0;
  for (const path of targets.paths) {
    const r = await fixRefusal(path, ctx.fs, boundary);
    if (r === 'none') continue;
    if (r) refused.push(r);
    else fixable++;
  }
  if (refused.length === 0) return result;

  // A folded result passes: it only carries the fix, so there's no message to
  // note it in — a partly refused one notes it in its fix description, where
  // `vaso fix` (and its dry run) reads what the fix will leave
  const note = result.passed ? '' : `; not changed by vaso fix: ${describe(refused)}`;
  if (fixable > 0 && result.passed) {
    return { ...result, fixDescription: `${result.fixDescription ? `${result.fixDescription}; ` : ''}not changed by vaso fix: ${describe(refused)}` };
  }
  if (fixable > 0) return { ...result, message: result.message + note };

  return {
    ...result,
    message: result.message + note,
    fixable: false,
    fixDescription: manualFix(targets.kind, refused, result.fixDescription),
  };
}

/** What to do by hand when vaso fix won't: the generic command where there is one. */
function manualFix(kind: FixTargets['kind'], refused: FixRefusal[], original: string | undefined): string {
  const why = 'vaso fix changes only regular files and folders inside the home (where its backup can restore them), never through a symlink or a hard link';
  if (kind === 'permissions') {
    const links = refused.some(r => r.kind === 'symlink' || r.kind === 'through-link');
    const paths = refused.slice(0, MAX_NAMED).map(r => shellQuote(r.path)).join(' ');
    const more = refused.length > MAX_NAMED ? ` (and the other ${refused.length - MAX_NAMED} listed)` : '';
    return `Remove group/other access yourself: ${codeSpan(`chmod go-rwx ${paths}`)}${more} — ${why}`
      + (links ? '; for a link, check where it points first (chmod changes the file it leads to)' : '');
  }
  const files = refused.slice(0, MAX_NAMED).map(r => r.path).join(', ') + (refused.length > MAX_NAMED ? ` and ${refused.length - MAX_NAMED} more` : '');
  return `${original ? `${original} — ` : ''}make this change by hand in ${files}: ${why}`;
}
