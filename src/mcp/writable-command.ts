import { basename, dirname, isAbsolute, resolve } from 'node:path';
import type { FSProvider, PermissionFacts } from '../core/fs-provider.js';
import { queryPermissions } from '../core/permissions.js';
import { uncollectedPath } from '../core/probe-coverage.js';
import { launchTarget, runnerName } from './source-resolver.js';

/**
 * Where any local user can replace an MCP server's command (or the script an
 * interpreter command runs) before it launches. `mode` is the octal mode as
 * printed in evidence: `777`, or `1777` for a sticky directory. `via`: the
 * path (a link's target) whose directory it is, when not the configured one.
 * `missing`: the file doesn't exist yet — anyone can plant it.
 * `foreignOwner`: in a sticky directory, `entry` (the file, a link, or the
 * subdirectory it is in) belongs to another user, uid `owner` — that user
 * can swap it. `foreignDirOwner`: the sticky directory itself belongs to
 * another user, uid `owner`, who can rename anything in it.
 * `barrier`: a directory on the way to it that other users can't traverse
 * (`/home/u (750)`) — nobody else reaches it, a mitigated finding.
 */
export type WritableCommandPath =
  | { kind: 'binary'; path: string; octal?: string; mode?: string; barrier?: string }
  | {
    kind: 'directory'; path: string; octal?: string; mode?: string; via?: string; missing?: boolean;
    foreignOwner?: boolean; foreignDirOwner?: boolean; owner?: number; entry?: string; barrier?: string;
  };

/** At most this many link hops are followed from a command (ELOOP-like). */
const MAX_LINK_HOPS = 40;

/** The setuid/setgid/sticky bit that keeps others from renaming entries they don't own. */
const STICKY = 0o1000;

/**
 * Owner of a path, or undefined when the provider can't tell. `entry`: of
 * the directory entry itself — a link's own owner, not its target's (who can
 * rename a link in a sticky directory is whoever owns the link).
 */
async function ownerOf(fs: FSProvider, path: string, entry = false): Promise<number | undefined> {
  return (await Promise.resolve().then(() => fs.ownership?.(path, entry ? { noFollow: true } : undefined)).catch(() => undefined))?.uid;
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

async function readLink(fs: FSProvider, path: string): Promise<string | undefined> {
  try {
    const target = await Promise.resolve(fs.readlink(path));
    return typeof target === 'string' ? target : undefined;
  } catch {
    return undefined;
  }
}

/**
 * The paths a command reaches through links: each hop's target, then its
 * real path — also for a dangling link, whose target anyone who can write
 * where it points may create.
 */
async function linkHops(fs: FSProvider, path: string): Promise<string[]> {
  const hops: string[] = [];
  let cur = path;
  for (let i = 0; i < MAX_LINK_HOPS; i++) {
    const target = await readLink(fs, cur);
    if (target === undefined) break;
    cur = isAbsolute(target) ? resolve(target) : resolve(dirname(cur), target);
    if (cur === path || hops.includes(cur)) break;
    hops.push(cur);
  }
  const real = await Promise.resolve().then(() => fs.realpath(path)).catch(() => undefined);
  if (real && real !== path && !hops.includes(real)) hops.push(real);
  return hops;
}

/** Whether something is at a path: a file or directory, or a link (even a dangling one). */
async function present(fs: FSProvider, path: string): Promise<boolean> {
  return (await Promise.resolve().then(() => fs.access(path)).catch(() => false)) || (await readLink(fs, path)) !== undefined;
}

/**
 * A snapshot recorded `path` as absent: the probe looked (a config-named
 * path, and the missing directories above it) and found nothing — locally
 * the stat fails the same way. Anything else a snapshot lacks is unknown.
 */
function knownAbsent(fs: FSProvider, path: string): boolean {
  return (fs as { collected?(p: string): boolean }).collected?.(path) === true;
}

/**
 * The directory on the way to `path` (by its real path; `path` itself
 * included when `self`) that keeps other users from reaching it, as
 * markUnreachable judges: anyone outside the group is stopped by one they
 * can't traverse, and the group's members (who get the group bits) by one
 * the group can't traverse — or by `target` not granting the group write.
 * A group that is its owner's private group (Linux) grants nobody else
 * access (queryPermissions drops its bits): a 750 home with a private group
 * is a barrier, one with a shared group (macOS `staff`) is not. Unknown
 * modes count as traversable.
 */
async function worldBarrier(fs: FSProvider, path: string, self: boolean, target: PermissionFacts): Promise<string | undefined> {
  let real = path;
  try {
    const r = await fs.realpath(path);
    if (isAbsolute(r)) real = r;
  } catch { /* judged by the configured spelling */ }
  let world: string | undefined;
  let group: string | undefined;
  for (let dir = self ? real : dirname(real); ; dir = dirname(dir)) {
    let facts: Awaited<ReturnType<typeof queryPermissions>> | undefined;
    try {
      facts = await queryPermissions(fs, dir);
    } catch {
      facts = undefined;
    }
    if (facts !== undefined && facts !== 'unsupported') {
      if (!world && !facts.worldExec) world = `${dir} (${facts.octal})`;
      if (!group && !facts.groupExec) group = `${dir} (${facts.octal})`;
    }
    if (dirname(dir) === dir) break;
  }
  if (!world) return undefined;
  return !target.groupWrite || group ? world : undefined;
}

type Level = Omit<Extract<WritableCommandPath, { kind: 'directory' }>, 'kind' | 'via'>;

/**
 * Whether someone other than root and the launching user can swap `child`
 * in world-writable `dir`: anyone when it isn't sticky or `child` doesn't
 * exist yet; in a sticky one, the directory's owner (who can rename anything
 * in it) or the entry's own owner. 'unknown': a snapshot doesn't record an
 * owner or the sticky bit.
 */
async function swapVerdict(
  fs: FSProvider, dir: string, octal: string | undefined, child: string, childExists: boolean | undefined, missing: boolean, trusted: Set<number>,
): Promise<Level | 'unknown' | undefined> {
  const snapshot = fs.kind === 'snapshot';
  const sticky = await isSticky(fs, dir);
  const hit: Level = { path: dir, octal, mode: sticky ? `1${octal}` : octal, ...(missing ? { missing: true } : {}) };
  if (sticky === false || childExists === false) return hit;
  const dirOwner = await ownerOf(fs, dir);
  if (dirOwner === undefined) return snapshot ? 'unknown' : hit;
  if (!trusted.has(dirOwner)) return { ...hit, foreignDirOwner: true, owner: dirOwner };
  const owner = childExists ? await ownerOf(fs, child, true) : undefined;
  if (owner === undefined) return snapshot ? 'unknown' : hit;
  if (!trusted.has(owner)) return { ...hit, foreignOwner: true, owner, entry: child };
  return sticky === undefined ? 'unknown' : undefined;
}

/**
 * The nearest directory on `path`'s way up to the root that lets any local
 * user swap what is at `path`: world-writable — a directory above the file's
 * own counts too, since renaming the subdirectory it is in swaps it — unless
 * sticky with both it and the entry below it owned by root or the launching
 * user (swapVerdict). One other users can't reach (a directory on the way
 * they can't traverse) is returned, with its `barrier`, only when no
 * reachable one is found — a finding all the same, so also over what a
 * snapshot can't judge. 'unknown': a snapshot doesn't record what is
 * needed to tell (a directory's mode, whether it is sticky, an owner).
 * `exists`: something (a file, a link) is at `path`; `missing`: the command
 * it leads to doesn't exist yet.
 */
async function swappableAbove(fs: FSProvider, path: string, exists: boolean, missing: boolean, trusted: Set<number>): Promise<Level | 'unknown' | undefined> {
  const snapshot = fs.kind === 'snapshot';
  let unknown = false;
  let blocked: Level | undefined;
  let child = path;
  let childExists: boolean | undefined = exists;
  for (let dir = dirname(path); ; dir = dirname(dir)) {
    let facts: Awaited<ReturnType<typeof queryPermissions>> | undefined;
    try {
      facts = await queryPermissions(fs, dir);
    } catch {
      facts = undefined;
    }
    // A directory a local stat doesn't find doesn't exist; a snapshot knows
    // that only for a directory the probe recorded as absent
    const absent = facts === undefined && (!snapshot || knownAbsent(fs, dir));
    if (facts === undefined || facts === 'unsupported') {
      if (snapshot && !absent) unknown = true;
    } else if (facts.worldWrite) {
      const hit = await swapVerdict(fs, dir, facts.octal, child, childExists, missing, trusted);
      if (hit === 'unknown') {
        unknown = true;
      } else if (hit) {
        const barrier = await worldBarrier(fs, dir, true, facts);
        if (!barrier) return hit;
        blocked ??= { ...hit, barrier };
      }
    }
    childExists = absent ? false : facts !== undefined ? true : undefined;
    child = dir;
    if (dirname(dir) === dir) break;
  }
  return blocked ?? (unknown ? 'unknown' : undefined);
}

/**
 * An absolute MCP command (or script) that is world-writable, or that any
 * local user can swap through a directory on its way up to the root, at the
 * configured path or where its links lead. `uncollected`: on a snapshot, the
 * path is outside what the probe collected, or the snapshot lacks what it
 * takes to judge it (an ancestor's mode, a sticky bit, an owner) — unknown,
 * not safe. A remote scan answers like a local one: the probe stats a path a
 * config names and records the modes and owners of its directories (of the
 * existing ones above it when it is missing) and its links.
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
    if (perms !== 'unsupported' && perms.worldWrite) {
      const barrier = await worldBarrier(fs, command, false, perms);
      return { kind: 'binary', path: command, octal: perms.octal, mode: perms.octal, ...(barrier ? { barrier } : {}) };
    }
  } catch {
    if (await uncollectedPath(fs, command)) return 'uncollected';
    exists = false;
  }
  const trusted = await trustedOwners(fs, options.config);
  let unknown = false;
  let blocked: WritableCommandPath | undefined;
  // A link that leads nowhere (or that the kernel won't follow: Linux
  // protected_symlinks) is there — whoever can rename it can swap it — and
  // whoever can write where it points can plant what it runs
  const isLink = !exists && (await readLink(fs, command)) !== undefined;
  for (const p of [command, ...await linkHops(fs, command)]) {
    const there = p === command ? exists || isLink : exists || await present(fs, p);
    const level = await swappableAbove(fs, p, there, !exists && !isLink, trusted);
    if (level === 'unknown') {
      unknown = true;
    } else if (level) {
      const found: WritableCommandPath = { kind: 'directory', ...level, ...(p !== command ? { via: p } : {}) };
      if (!level.barrier) return found;
      blocked ??= found;
    }
  }
  return blocked ?? (unknown ? 'uncollected' : undefined);
}

/**
 * How an interpreter reads its arguments, for the script it runs: options
 * that take the next word as their value (or the rest of a short-option
 * cluster: `-I/dir`), options whose value is code run instead of a script
 * (`perl -e`), the script itself (`php -f x`, `java -jar x`) or a file
 * loaded first (`ruby -r /x.rb`). `commandString`: a shell, whose `-c` makes
 * the first operand a command line and `-s` reads the script from stdin.
 * `operand`: the first operand is a script only when it matches (java runs a
 * class by name, or a source file). `wordOptions`: options are whole words
 * even with one dash (`java -jar`), never clusters of letters.
 */
interface RunnerSyntax {
  value: ReadonlySet<string>;
  code?: ReadonlySet<string>;
  script?: ReadonlySet<string>;
  preload?: ReadonlySet<string>;
  commandString?: boolean;
  operand?: RegExp;
  wordOptions?: boolean;
}

const SHELL: RunnerSyntax = { value: new Set(['-o', '+o', '-O', '+O', '--rcfile', '--init-file']), commandString: true };

const SCRIPT_RUNNERS: Readonly<Record<string, RunnerSyntax>> = {
  sh: SHELL, bash: SHELL, zsh: SHELL, dash: SHELL, ksh: SHELL,
  fish: { value: new Set(['-C', '--init-command', '-d', '--debug', '-o', '--debug-output', '-f', '--features']), code: new Set(['-c', '--command']) },
  perl: { value: new Set(['-I']), code: new Set(['-e', '-E']) },
  ruby: { value: new Set(['-I', '-C', '-E', '--encoding']), code: new Set(['-e']), preload: new Set(['-r']) },
  php: { value: new Set(['-c', '-d', '-z', '-t']), code: new Set(['-r', '-R', '-B', '-E']), script: new Set(['-f', '-F']) },
  lua: { value: new Set(['-e', '-l']) },
  osascript: { value: new Set(['-l', '-s']), code: new Set(['-e']) },
  java: {
    value: new Set(['-cp', '-classpath', '--class-path', '-p', '--module-path', '--add-modules', '--add-opens', '--add-exports', '--add-reads', '--enable-native-access']),
    code: new Set(['-m', '--module']),
    script: new Set(['-jar']),
    operand: /\.java$/,
    wordOptions: true,
  },
};

/** The absolute files a script runner runs, per its syntax. */
function runnerScripts(syntax: RunnerSyntax, args: readonly string[]): string[] {
  const out: string[] = [];
  const add = (p: string | undefined) => { if (p && isAbsolute(p)) out.push(p); };
  const takes = (flag: string) => syntax.value.has(flag) || !!syntax.code?.has(flag) || !!syntax.script?.has(flag) || !!syntax.preload?.has(flag);
  /** An option with its value: true when no script follows. */
  const option = (flag: string, value: string | undefined): boolean => {
    if (syntax.code?.has(flag)) return true;
    if (syntax.script?.has(flag)) { add(value); return true; }
    if (syntax.preload?.has(flag)) add(value);
    return false;
  };
  let commandLine = false;
  const operand = (arg: string) => {
    // `bash -c '/x/run.sh --flag'`: the command line's first word
    if (commandLine) add(arg.trim().split(/\s+/)[0]);
    else if (!syntax.operand || syntax.operand.test(arg)) add(arg);
  };
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === '--') {
      if (args[i + 1] !== undefined) operand(args[i + 1]);
      break;
    }
    if (arg === '-') break; // reads its script from stdin
    if (arg.startsWith('--') || (syntax.wordOptions && arg.startsWith('-'))) {
      const eq = arg.indexOf('=');
      const flag = eq < 0 ? arg : arg.slice(0, eq);
      if (takes(flag) && option(flag, eq < 0 ? args[++i] : arg.slice(eq + 1))) break;
      continue;
    }
    if (arg.length > 1 && (arg.startsWith('-') || (arg.startsWith('+') && syntax.commandString))) {
      let done = false;
      for (let k = 1; k < arg.length; k++) {
        const flag = arg[0] + arg[k];
        if (syntax.commandString && flag === '-c') { commandLine = true; continue; }
        if (syntax.commandString && flag === '-s') { done = true; break; }
        if (takes(flag)) {
          done = option(flag, arg.slice(k + 1) || args[++i]);
          break;
        }
      }
      if (done) break;
      continue;
    }
    operand(arg);
    break;
  }
  return out;
}

/** `NAME=value`, a word `env` sets in the environment. */
const ENV_ASSIGNMENT = /^[A-Za-z_][A-Za-z0-9_]*=/;
/** `env` options that take the next word as their value. */
const ENV_VALUE_FLAGS = new Set(['-u', '--unset', '-C', '--chdir', '-P']);

/**
 * The command `env [options] [NAME=value…] command args…` runs, with its
 * arguments — `-S`/`--split-string` splits its value into words first.
 */
function envCommand(args: readonly string[]): { command: string; args: string[] } | undefined {
  let rest = [...args];
  for (let i = 0; i < rest.length; i++) {
    const arg = rest[i];
    const split = arg === '-S' || arg === '--split-string' ? rest[i + 1]
      : arg.startsWith('--split-string=') ? arg.slice('--split-string='.length)
        : /^-S./.test(arg) ? arg.slice(2) : undefined;
    if (split !== undefined) {
      rest = [...split.trim().split(/\s+/).filter(Boolean), ...rest.slice(i + (arg === '-S' || arg === '--split-string' ? 2 : 1))];
      i = -1;
      continue;
    }
    if (arg === '--') return rest[i + 1] !== undefined ? { command: rest[i + 1], args: rest.slice(i + 2) } : undefined;
    if (ENV_VALUE_FLAGS.has(arg)) { i++; continue; }
    if (arg.startsWith('-') || ENV_ASSIGNMENT.test(arg)) continue;
    return { command: arg, args: rest.slice(i + 1) };
  }
  return undefined;
}

/**
 * The local files an interpreter command runs, as the config names them by
 * absolute path: `node /x/server.js`, `python3 /x/s.py`, `deno run /x/m.ts`,
 * `bash -o pipefail /x/run.sh`, `java -jar /x/s.jar`, modules preloaded with
 * `-r`/`--import`, and through `env [NAME=value…] cmd …` the command and
 * what it runs. Relative paths depend on the client's working directory and
 * are not judged. A path is judged only as the config spells it — a whole
 * argument, an `--option=` value, or a word of one (`env -S`, `bash -c`) —
 * which is what a remote probe stats.
 */
export function interpreterScripts(command: string, args: readonly string[]): string[] {
  const named = (p: string) => args.some(a => a === p || a.endsWith(`=${p}`) || a === `file://${p}` || a.trim().split(/\s+/).includes(p));
  const runner = basename(runnerName(command)).toLowerCase();
  if (runner === 'env') {
    const inner = envCommand(args);
    if (!inner) return [];
    const out = isAbsolute(inner.command) ? [inner.command] : [];
    return [...new Set([...out, ...interpreterScripts(inner.command, inner.args)].filter(named))];
  }
  const target = launchTarget({ name: '', command, args: [...args], transport: 'stdio' });
  const out = target.executed ? [] : [target.entry, ...target.preloads].filter((p): p is string => !!p && isAbsolute(p) && named(p));
  const syntax = Object.hasOwn(SCRIPT_RUNNERS, runner) ? SCRIPT_RUNNERS[runner] : undefined;
  if (out.length === 0 && syntax) out.push(...runnerScripts(syntax, args).filter(named));
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
 * `unverified` collects the paths a snapshot can't judge (each once).
 *
 * `hermes`: the client strips the command and expands a leading `~` in it
 * (Hermes' `_resolve_stdio_command`), and `${VAR}` references in the config
 * were expanded from its environment — one a snapshot doesn't hold (only
 * `HOME` and the variables the probe ships) leaves a value not verified.
 */
export async function writableLaunchPaths(
  fs: FSProvider,
  command: string,
  args: readonly string[],
  unverified: string[],
  options: { config?: string; hermes?: boolean } = {},
): Promise<WritableLaunchPath[]> {
  const note = (p: string) => { if (!unverified.includes(p)) unverified.push(p); };
  let cmd = command;
  if (options.hermes) {
    cmd = cmd.trim();
    if (cmd === '~' || cmd.startsWith('~/')) cmd = fs.homedir().replace(/\/$/, '') + cmd.slice(1);
    if (fs.kind === 'snapshot') for (const v of [cmd, ...args]) if (v.includes('${')) note(v.trim());
  }
  const targets: Array<{ role: WritableLaunchPath['role']; path: string }> = [];
  if (cmd.startsWith('/')) targets.push({ role: 'command', path: cmd });
  for (const s of interpreterScripts(cmd, args)) if (s !== cmd) targets.push({ role: 'script', path: s });
  const out: WritableLaunchPath[] = [];
  for (const t of targets) {
    const writable = await worldWritableCommandPath(fs, t.path, options);
    if (writable === 'uncollected') note(t.path);
    else if (writable) out.push({ ...t, writable });
  }
  return out;
}

/**
 * Evidence text for a writable launch path: `where` follows the configured
 * value in a snippet (` (mode 777)` for the file, `: <dir> (mode 777)` for a
 * directory), `detail` says who can do what. `mitigated`: other users can't
 * reach it (a directory on the way they can't traverse) — said in `detail`.
 */
export function writableLaunchText(w: WritableLaunchPath): { where: string; detail: string; mitigated: boolean } {
  const what = w.role === 'command' ? 'MCP server command' : 'Script the MCP server runs';
  const v = w.writable;
  const barrier = v.barrier ? ` — mitigated: not reachable by other users, parent ${v.barrier} blocks traversal` : '';
  if (v.kind === 'binary') {
    return {
      where: ` (mode ${v.mode ?? v.octal})`,
      detail: `${what} ${w.path} is world-writable — any local user can replace it before launch${barrier}`,
      mitigated: !!v.barrier,
    };
  }
  const link = v.via ? ` (its link leads to ${v.via})` : '';
  const place = dirname(v.via ?? w.path) === v.path ? `its directory ${v.path}` : `${v.path}, a directory above it,`;
  const action = v.missing ? `plant ${w.path}, which doesn't exist yet,` : `swap ${w.path}`;
  let state = v.mode?.length === 4 ? ' (sticky)' : '';
  let who = 'any local user';
  if (v.foreignDirOwner) {
    state = ` and sticky, but the directory belongs to another user (uid ${v.owner})`;
    who = 'that user (or root)';
  } else if (v.foreignOwner) {
    const entry = v.entry === undefined || v.entry === (v.via ?? w.path) ? 'it' : v.entry;
    state = ` and sticky, but ${entry} belongs to another user (uid ${v.owner})`;
    who = 'that user (or root)';
  }
  return {
    where: `: ${v.path} (mode ${v.mode ?? v.octal})`,
    detail: `${what}${link}: ${place} is world-writable${state} — ${who} can ${action} before launch${barrier}`,
    mitigated: !!v.barrier,
  };
}
