import { basename, dirname, isAbsolute, resolve } from 'node:path';
import type { FSProvider } from '../core/fs-provider.js';
import { queryPermissions } from '../core/permissions.js';
import { uncollectedPath } from '../core/probe-coverage.js';
import { launchTarget, runnerName } from './source-resolver.js';

/**
 * Where any local user can replace an MCP server's command (or the script an
 * interpreter command runs) before it launches. `mode` is the octal mode as
 * printed in evidence: `777`, or `1777` for a sticky directory. `via`: the
 * path (a link's target) whose directory it is, when not the configured one.
 * `missing`: the file doesn't exist yet — anyone can plant it.
 * `foreignOwner`: what is in the (sticky) directory belongs to another user.
 */
export type WritableCommandPath =
  | { kind: 'binary'; path: string; octal?: string; mode?: string }
  | { kind: 'directory'; path: string; octal?: string; mode?: string; via?: string; missing?: boolean; foreignOwner?: boolean };

/** At most this many link hops are followed from a command (ELOOP-like). */
const MAX_LINK_HOPS = 40;

/** The setuid/setgid/sticky bit that keeps others from renaming entries they don't own. */
const STICKY = 0o1000;

/** Owner of a path, or undefined when the provider can't tell. */
async function ownerOf(fs: FSProvider, path: string): Promise<number | undefined> {
  return (await Promise.resolve().then(() => fs.ownership?.(path)).catch(() => undefined))?.uid;
}

/**
 * Whether a world-writable directory is sticky (1777, like /tmp). A snapshot
 * from a probe that records permission bits only can't say: a root-owned one
 * (the shared /tmp, /var/tmp, /Users/Shared — sticky as installed) is
 * unknown; one a user made world-writable is taken as not sticky, as such
 * directories are, so a remote scan keeps flagging them (and a user's own
 * sticky directory is flagged remotely only — the conservative side).
 */
async function isSticky(fs: FSProvider, dir: string): Promise<boolean | undefined> {
  if (fs.kind === 'snapshot' && !(fs as { recordsSpecialModeBits?(): boolean }).recordsSpecialModeBits?.()) {
    const owner = await ownerOf(fs, dir);
    return owner === undefined || owner === 0 ? undefined : false;
  }
  try {
    return ((await fs.stat(dir)).mode & STICKY) !== 0;
  } catch {
    return undefined;
  }
}

/**
 * Owners a sticky directory protects the command for: root and whoever runs
 * it — the owner of the config that launches it (the user's home when the
 * config's owner is unknown).
 */
async function trustedOwners(fs: FSProvider, config: string | undefined): Promise<Set<number>> {
  const launcher = (config ? await ownerOf(fs, config) : undefined) ?? await ownerOf(fs, fs.homedir());
  return new Set(launcher === undefined ? [0] : [0, launcher]);
}

/** The paths a command reaches through links: each hop's target, then its real path. */
async function linkHops(fs: FSProvider, path: string): Promise<string[]> {
  const hops: string[] = [];
  let cur = path;
  for (let i = 0; i < MAX_LINK_HOPS; i++) {
    let target: string;
    try {
      target = await Promise.resolve(fs.readlink(cur));
      if (typeof target !== 'string') break;
    } catch {
      break;
    }
    cur = isAbsolute(target) ? resolve(target) : resolve(dirname(cur), target);
    if (cur === path || hops.includes(cur)) break;
    hops.push(cur);
  }
  const real = await Promise.resolve().then(() => fs.realpath(path)).catch(() => undefined);
  if (real && real !== path && !hops.includes(real)) hops.push(real);
  return hops;
}

type Level = Omit<Extract<WritableCommandPath, { kind: 'directory' }>, 'kind' | 'via'>;

/**
 * The nearest directory on `path`'s way up to the root that lets any local
 * user swap what is at `path`: world-writable — a directory above the file's
 * own counts too, since renaming the subdirectory it is in swaps it — unless
 * sticky with the entry below it owned by root or the launching user (others
 * can't rename or delete it there). 'unknown': a snapshot doesn't record what
 * is needed to tell (a directory's mode, whether it is sticky, an owner).
 */
async function swappableAbove(fs: FSProvider, path: string, exists: boolean, trusted: Set<number>): Promise<Level | 'unknown' | undefined> {
  const snapshot = fs.kind === 'snapshot';
  let unknown = false;
  let child = path;
  // Whether the entry below `dir` on the way up exists; undefined: a snapshot can't tell
  let childExists: boolean | undefined = exists;
  for (let dir = dirname(path); ; dir = dirname(dir)) {
    let facts: Awaited<ReturnType<typeof queryPermissions>> | undefined;
    try {
      facts = await queryPermissions(fs, dir);
    } catch {
      facts = undefined;
    }
    if (facts === undefined || facts === 'unsupported') {
      // Locally: a directory that doesn't exist (a command not installed
      // yet) — whoever can create it can plant the command. A snapshot that
      // didn't record the directory's mode can't tell
      if (snapshot) unknown = true;
    } else if (facts.worldWrite) {
      const sticky = await isSticky(fs, dir);
      const mode = sticky ? `1${facts.octal}` : facts.octal;
      const hit: Level = { path: dir, octal: facts.octal, mode, ...(exists ? {} : { missing: true }) };
      // Not sticky, or nothing there yet to protect: anyone can put their own file in its place
      if (sticky === false || childExists === false) return hit;
      const owner = childExists ? await ownerOf(fs, child) : undefined;
      if (owner === undefined) {
        if (snapshot) unknown = true;
        else return hit;
      } else if (!trusted.has(owner)) {
        return { ...hit, foreignOwner: true };
      } else if (sticky === undefined) {
        unknown = true;
      }
    }
    childExists = facts !== undefined ? true : snapshot ? undefined : false;
    child = dir;
    if (dirname(dir) === dir) break;
  }
  return unknown ? 'unknown' : undefined;
}

/**
 * An absolute MCP command (or script) that is world-writable, or that any
 * local user can swap through a directory on its way up to the root, at the
 * configured path or where its links lead. `uncollected`: on a snapshot, the
 * path is outside what the probe collected, or the snapshot lacks what it
 * takes to judge it (an ancestor's mode, a sticky bit, an owner) — unknown,
 * not safe. A remote scan answers like a local one: the probe stats a path a
 * config names and records the modes of its directories and its links.
 *
 * `config`: the config file that launches it — its owner is who a sticky
 * directory protects the command for.
 */
export async function worldWritableCommandPath(
  fs: FSProvider,
  command: string,
  options: { config?: string } = {},
): Promise<WritableCommandPath | 'uncollected' | undefined> {
  let exists = true;
  try {
    const perms = await queryPermissions(fs, command);
    if (perms !== 'unsupported' && perms.worldWrite) return { kind: 'binary', path: command, octal: perms.octal, mode: perms.octal };
  } catch {
    if (await uncollectedPath(fs, command)) return 'uncollected';
    exists = false;
  }
  const trusted = await trustedOwners(fs, options.config);
  let unknown = false;
  for (const p of [command, ...(exists ? await linkHops(fs, command) : [])]) {
    const level = await swappableAbove(fs, p, exists, trusted);
    if (level === 'unknown') unknown = true;
    else if (level) return { kind: 'directory', ...level, ...(p !== command ? { via: p } : {}) };
  }
  return unknown ? 'uncollected' : undefined;
}

/** Shells and interpreters whose first non-option argument is the script they run. */
const SCRIPT_RUNNERS = new Set(['sh', 'bash', 'zsh', 'dash', 'ksh', 'fish', 'ruby', 'perl', 'php', 'lua', 'osascript']);

/**
 * The local files an interpreter command runs, as the config names them by
 * absolute path: `node /x/server.js`, `python3 /x/s.py`, `deno run /x/m.ts`,
 * `bash /x/run.sh`, modules preloaded with `-r`/`--import`. Relative paths
 * depend on the client's working directory and are not judged.
 */
export function interpreterScripts(command: string, args: readonly string[]): string[] {
  const named = (p: string) => args.some(a => a === p || a.endsWith(`=${p}`) || a === `file://${p}`);
  const target = launchTarget({ name: '', command, args: [...args], transport: 'stdio' });
  const out = target.executed ? [] : [target.entry, ...target.preloads].filter((p): p is string => !!p && isAbsolute(p) && named(p));
  if (out.length === 0 && SCRIPT_RUNNERS.has(basename(runnerName(command)).toLowerCase())) {
    const first = args.find(a => !a.startsWith('-'));
    if (first && isAbsolute(first)) out.push(first);
  }
  return [...new Set(out)];
}

/** One judged path of a server's launch: its command, or a script the command runs. */
export interface WritableLaunchPath {
  role: 'command' | 'script';
  path: string;
  writable: WritableCommandPath;
}

/**
 * Every absolute path a stdio server's launch runs — the command, and the
 * scripts an interpreter command runs — that any local user can replace.
 * `unverified` collects the paths a snapshot can't judge.
 */
export async function writableLaunchPaths(
  fs: FSProvider,
  command: string,
  args: readonly string[],
  unverified: string[],
  options: { config?: string } = {},
): Promise<WritableLaunchPath[]> {
  const targets: Array<{ role: WritableLaunchPath['role']; path: string }> = [];
  if (command.startsWith('/')) targets.push({ role: 'command', path: command });
  for (const s of interpreterScripts(command, args)) if (s !== command) targets.push({ role: 'script', path: s });
  const out: WritableLaunchPath[] = [];
  for (const t of targets) {
    const writable = await worldWritableCommandPath(fs, t.path, options);
    if (writable === 'uncollected') unverified.push(t.path);
    else if (writable) out.push({ ...t, writable });
  }
  return out;
}

/**
 * Evidence text for a writable launch path: `where` follows the configured
 * value in a snippet (` (mode 777)` for the file, `: <dir> (mode 777)` for a
 * directory), `detail` says what any local user can do.
 */
export function writableLaunchText(w: WritableLaunchPath): { where: string; detail: string } {
  const what = w.role === 'command' ? 'MCP server command' : 'Script the MCP server runs';
  const v = w.writable;
  if (v.kind === 'binary') {
    return { where: ` (mode ${v.mode ?? v.octal})`, detail: `${what} ${w.path} is world-writable — any local user can replace it before launch` };
  }
  const link = v.via ? ` (its link leads to ${v.via})` : '';
  const place = dirname(v.via ?? w.path) === v.path ? `its directory ${v.path}` : `${v.path}, a directory above it,`;
  const sticky = v.mode?.length !== 4 ? '' : v.foreignOwner ? ' (sticky, but what is in it belongs to another user)' : ' (sticky)';
  const action = v.missing ? `plant ${w.path}, which doesn't exist yet,` : `swap ${w.path}`;
  return {
    where: `: ${v.path} (mode ${v.mode ?? v.octal})`,
    detail: `${what}${link}: ${place} is world-writable${sticky} — any local user can ${action} before launch`,
  };
}
