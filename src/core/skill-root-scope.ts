import { basename, dirname, isAbsolute, join, normalize, posix, relative } from 'node:path';
import type { FSProvider } from './fs-provider.js';
import type { UnscannedSkillsDir } from './types.js';
import { SENSITIVE_SINKS, classifySensitivePath } from '../analyzers/sensitive-paths.js';
import {
  configTreeGap, configTreeStatus, expandManifestGlob, expandedGlobRegex, manifestCoversTree, manifestSkillGlobs, pathChain, splitGlob,
} from './probe-coverage.js';
import { relEscapes } from './path-rel.js';
import { MAX_LINKED_SKILL_ENTRIES, MAX_SKILL_TREE_ENTRIES, planSkillLinks, scanSkillTree } from './skill-tree-count.js';
import type { LinkVerdict, TreeScan } from './skill-tree-count.js';

/**
 * Where a skills tree may be walked from, and where a link met while walking
 * one may lead. A skills directory an agent's config sets (an OpenClaw
 * extraDir, a Nanobot or ZeroClaw workspace), or an agent's own default one
 * that a link takes out of the home (`~/.claude/skills` → a home-manager
 * store, `~/.claude` → another volume), is walked wherever it is — except
 * in these places, judged on the path as written and once resolved:
 *
 *   - the filesystem root;
 *   - the scanned user's home itself, or a directory above it;
 *   - another user's home (/home/<u>, /Users/<u> but not /Users/Shared,
 *     /root, and /home or /Users themselves) — one holding the scanned home
 *     is that home's ancestor;
 *   - an OS directory (/etc, /usr, /var, /bin, /sbin, /lib*, /System,
 *     /Library, /dev, /proc, /sys, /boot, /run; /private/etc and
 *     /private/var) — unless inside the scanned home;
 *   - a credential store or sensitive location (SENSITIVE_SINKS).
 *
 * /opt, /srv, /nix/store, /Volumes/*, /mnt/*, /media/*, /tmp and
 * /Users/Shared are not refused. Such a directory is reported "not scanned" (SKL-002) by local and
 * remote scans alike: the probe applies the same rule (probe/skill_scope.go,
 * treeAllowed), and probe/testdata/skill-scope-cases.json holds the table
 * both sides test. A link inside a walked tree follows it too
 * (walkSkillTree).
 *
 * On a snapshot, what the probe recorded for a tree (configTrees) decides: it
 * judged the real filesystem, whose links a snapshot only partly records.
 */

function strictlyWithin(p: string, dir: string): boolean {
  const rel = relative(dir, p);
  return rel !== '' && !relEscapes(rel) && !isAbsolute(rel);
}

/** `p` is `dir` or inside it. */
function within(p: string, dir: string): boolean {
  const rel = relative(dir, p);
  return rel === '' || (!relEscapes(rel) && !isAbsolute(rel));
}

/** A path cleaned like Go's filepath.Clean (no trailing slash but `/`). */
function clean(p: string): string {
  return normalize(p).replace(/(.)\/$/, '$1');
}

/**
 * A skills directory a config sets, as both scans key it: an absolute one
 * cleaned (`/tmp/./x`, `/tmp//x/`, `/etc/../tmp/x` → `/tmp/x`), as the probe
 * records the tree it walked; a relative one as written.
 */
export function cleanSkillRoot(p: string): string {
  return isAbsolute(p) ? clean(p) : p;
}

/** Top-level OS directories (lower case); `lib*` too. */
const SYSTEM_TOPS = new Set(['etc', 'usr', 'var', 'bin', 'sbin', 'system', 'library', 'dev', 'proc', 'sys', 'boot', 'run']);

/** The user home (or home area) `parts` lie in, by location; '' otherwise.
 *  macOS's /Users/Shared is a shared folder, no user's home. */
function otherHomeDir(parts: readonly string[]): string {
  const top = parts[0].toLowerCase();
  switch (top) {
    case 'home':
    case 'users':
      if (parts.length === 1) return `/${parts[0]}`;
      if (top === 'users' && parts[1].toLowerCase() === 'shared') return '';
      return `/${parts[0]}/${parts[1]}`;
    case 'root':
      return `/${parts[0]}`;
  }
  return '';
}

/**
 * Why `path` is not a place a skills tree is walked — "root", "home" (the
 * scanned home or above), "other-home:<dir>", "system:/<top>",
 * "sink:<index into SENSITIVE_SINKS>" — sorted; empty when it is one. `own`
 * are the spellings of the tree's user's home (none for a tree in no
 * scanned home), `all` every scanned home's spellings, own included. A pure
 * function of its strings, identical to scopeLabels in probe/skill_scope.go.
 */
export function scopeLabels(path: string, own: readonly string[], all: readonly string[]): string[] {
  const p = clean(path);
  if (p === '/') return ['root'];
  for (const h of all) if (within(clean(h), p)) return ['home'];
  const out: string[] = [];
  SENSITIVE_SINKS.forEach((s, i) => { if (s.re.test(p)) out.push(`sink:${i}`); });
  for (const h of own) if (strictlyWithin(p, clean(h))) return out.sort();
  const parts = p.slice(1).split('/');
  let sys = parts;
  if (parts[0].toLowerCase() === 'private') {
    if (parts.length === 1) out.push('system:/private');
    else if (['etc', 'var'].includes(parts[1].toLowerCase())) sys = parts.slice(1);
  }
  const top = sys[0].toLowerCase();
  if (SYSTEM_TOPS.has(top) || top.startsWith('lib')) out.push(`system:/${top}`);
  const homeDir = otherHomeDir(parts);
  if (homeDir !== '' && !all.some(h => within(clean(h), homeDir))) out.push(`other-home:${homeDir}`);
  return out.sort();
}

/**
 * `p` resolved like a realpath for as much of it as exists; the rest
 * appended. On a snapshot, a linked home's other spelling resolves through
 * what the probe recorded for it (resolvedDirs): the link itself isn't in
 * the snapshot.
 */
async function resolveExisting(fs: FSProvider, p: string): Promise<string> {
  const viaLinks = await realpathExisting(fs, p);
  const recorded = (fs as { resolvedDir?(path: string): string }).resolvedDir?.(viaLinks) ?? viaLinks;
  return recorded === viaLinks ? viaLinks : realpathExisting(fs, recorded);
}

async function realpathExisting(fs: FSProvider, p: string): Promise<string> {
  const tail: string[] = [];
  for (let cur = p; ; cur = dirname(cur)) {
    try {
      return join(await fs.realpath(cur), ...tail);
    } catch {
      if (dirname(cur) === cur) return p;
      tail.unshift(basename(cur));
    }
  }
}

/** The spellings (written, resolved) of `home`, and of every home a tree is judged against. */
async function scopeHomes(fs: FSProvider, home: string | undefined): Promise<{ own: string[]; all: string[] }> {
  const add = async (list: string[], h: string | undefined) => {
    if (!h || !isAbsolute(h)) return;
    for (const s of [clean(h), clean(await resolveExisting(fs, clean(h)))]) if (!list.includes(s)) list.push(s);
  };
  const own: string[] = [];
  await add(own, home);
  const all = [...own];
  await add(all, homedirOf(fs));
  return { own, all };
}

/** The scanned user's home, when the provider knows it. */
function homedirOf(fs: FSProvider): string | undefined {
  try {
    const h = typeof fs.homedir === 'function' ? fs.homedir() : undefined;
    return typeof h === 'string' && isAbsolute(h) ? h : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Every label of `p` once resolved, and as written — of the written spelling
 * only its credential stores when `p` resolves into the home (a link to the
 * home is the home, wherever the link is).
 */
async function pathScope(fs: FSProvider, p: string, own: readonly string[], all: readonly string[]): Promise<Set<string>> {
  const written = clean(p);
  const real = clean(await resolveExisting(fs, written));
  const set = new Set(scopeLabels(real, own, all));
  const inHome = own.some(h => strictlyWithin(real, clean(h)));
  for (const l of scopeLabels(written, own, all)) if (!inHome || l.startsWith('sink:')) set.add(l);
  return set;
}

/** A skills tree of the user whose home is `home` may be walked from `dir` (see the module comment). */
export async function skillTreeAllowed(fs: FSProvider, dir: string, home: string): Promise<boolean> {
  if (!isAbsolute(dir) || !isAbsolute(home)) return false;
  const h = clean(home);
  if (h === '/') return false;
  const { own, all } = await scopeHomes(fs, h);
  return (await pathScope(fs, dir, own, all)).size === 0;
}

/**
 * For a walk of the skills tree at `root`: whether a link in it may be
 * followed (or the file behind it read) — what it leads to, as written and
 * resolved, carries no label the root itself doesn't (a bundled tree under
 * /usr may link within /usr; a tree in the home may not link into /etc,
 * another user's home or a credential store). probe/skill_scope.go
 * linkInScope.
 */
export async function linkScope(fs: FSProvider, root: string): Promise<(link: string) => Promise<boolean>> {
  if (!isAbsolute(root)) return async () => true;
  // judged on the first link met: most trees have none
  let scope: Promise<{ own: string[]; all: string[]; allowed: Set<string> }> | undefined;
  const load = async () => {
    const me = homedirOf(fs);
    const home = me ? await homeOfDir(fs, root, [me]) : undefined;
    const { own, all } = await scopeHomes(fs, home);
    return { own, all, allowed: await pathScope(fs, root, own, all) };
  };
  return async (link: string) => {
    if (!scope) scope = load();
    const { own, all, allowed } = await scope;
    const targets = [link];
    try {
      const raw = await fs.readlink(link);
      targets.push(isAbsolute(raw) ? raw : join(dirname(link), raw));
    } catch {
      // the link as resolved is enough
    }
    for (const t of targets) {
      for (const l of await pathScope(fs, t, own, all)) if (!allowed.has(l)) return false;
    }
    return true;
  };
}

/** `dir` lies strictly inside `home`, as written or once both are resolved. */
export async function withinHome(fs: FSProvider, dir: string, home: string): Promise<boolean> {
  if (!isAbsolute(dir) || !isAbsolute(home)) return false;
  const p = normalize(dir);
  const h = clean(home);
  if (strictlyWithin(p, h)) return true;
  return strictlyWithin(await resolveExisting(fs, p), await resolveExisting(fs, h));
}

/** `dir` is the user's home itself, as written or once resolved. */
async function isHomeItself(fs: FSProvider, dir: string, home: string): Promise<boolean> {
  if (!isAbsolute(dir) || !isAbsolute(home)) return false;
  if (clean(dir) === clean(home)) return true;
  return clean(await resolveExisting(fs, clean(dir))) === clean(await resolveExisting(fs, clean(home)));
}

/**
 * Why a skills directory is not scanned, or undefined when it is: the home
 * itself (`home`), somewhere no skills tree is walked (`outside` — the
 * probe reports such trees `refused`), or over the skills-tree entry limit
 * (`limit`, MAX_SKILL_TREE_ENTRIES — the probe's maxConfigTreeEntries), which
 * a config-set tree and an agent's own tree the probe walks as a
 * config-derived one (linkedManifestBase) hold to, locally as remotely. An
 * agent's own default tree (one the manifest walks) is judged only when it
 * lies in the home as written: a link may take it elsewhere.
 */
export async function skillRootGap(fs: FSProvider, dir: string, home: string): Promise<UnscannedSkillsDir['reason'] | undefined> {
  if (!isAbsolute(dir)) return 'relative';
  const refused = async (): Promise<UnscannedSkillsDir['reason']> => ((await isHomeItself(fs, dir, home)) ? 'home' : 'outside');
  if (manifestCoversTree(fs, dir)) {
    // An agent's own tree: walked, unless it lies in the home as written and
    // a link takes it where no skills tree is walked (the probe walks one
    // that leaves the home as a config-derived tree: linkedOutSkillBase)
    if (fs.kind === 'snapshot') {
      const gap = configTreeGap(fs, dir);
      return gap === 'refused' ? refused() : gap;
    }
    const p = normalize(dir);
    if (!isAbsolute(home) || !strictlyWithin(p, clean(home)) || classifySensitivePath(p).length > 0) return undefined;
    if (!(await skillTreeAllowed(fs, dir, home))) return refused();
    // One the probe walks as a config-derived tree (a link takes it, or a
    // wildcard directory above it, elsewhere) holds to its entry limit
    const base = await linkedManifestBase(fs, p, home);
    return base !== undefined && (await skillTreeAllowed(fs, base, home)) && (await overEntryLimit(fs, base)) ? 'limit' : undefined;
  }
  if (fs.kind === 'snapshot') {
    const status = configTreeStatus(fs, dir);
    if (status === 'collected') return undefined;
    if (status === 'limit' || status === 'total') return status;
    if (status === 'refused') return refused();
  }
  if (await isHomeItself(fs, dir, home)) return 'home';
  if (!(await skillTreeAllowed(fs, dir, home))) return 'outside';
  const gap = configTreeGap(fs, dir);
  if (gap) return gap === 'refused' ? 'outside' : gap;
  // Local: the probe's entry limit, judged the same way before any of it is read
  if (fs.kind !== 'snapshot' && (await overEntryLimit(fs, normalize(dir)))) return 'limit';
  return undefined;
}

const scanCache = new WeakMap<FSProvider, Map<string, Promise<TreeScan>>>();

/**
 * The skills tree at `dir` scanned to the entry limit (scanSkillTree),
 * remembered per provider by where `dir` leads: adapters and the registry
 * ask again, and two hundred links to one tree count it once.
 */
async function limitScan(fs: FSProvider, dir: string): Promise<TreeScan> {
  let byReal = scanCache.get(fs);
  if (!byReal) scanCache.set(fs, (byReal = new Map()));
  let real: string;
  try {
    real = await fs.realpath(dir);
  } catch {
    real = clean(dir);
  }
  let hit = byReal.get(real);
  if (!hit) {
    hit = scanSkillTree(fs, real, MAX_SKILL_TREE_ENTRIES).catch(() => ({ n: 0, links: [] }));
    byReal.set(real, hit);
  }
  return hit;
}

/**
 * The skills tree at `dir` holds more entries than a scan walks
 * (MAX_SKILL_TREE_ENTRIES, counted as the probe counts: skill-tree-count.ts)
 * — its own entries: a directory link in it counts as one, and is judged on
 * its own when the tree is walked (linkCap).
 */
export async function overEntryLimit(fs: FSProvider, dir: string): Promise<boolean> {
  return (await limitScan(fs, dir)).n > MAX_SKILL_TREE_ENTRIES;
}

const planCache = new WeakMap<FSProvider, Map<string, Promise<Map<string, LinkVerdict>>>>();

/** Why a walk leaves a directory link out for its size. */
export type LinkCapReason = 'limit' | 'total';

/**
 * For a walk of the skills tree at `root`: whether a directory link met in
 * it (one the walk would follow) is left out for the size of what it leads
 * to — a tree over the entry limit (`limit`), or one past what the tree's
 * links may hold together (`total`, MAX_LINKED_SKILL_ENTRIES) — as
 * planSkillLinks decides by its target, the same way the probe's linkPlan
 * does; a link the plan gives no verdict is judged by its own count. The
 * plain content of the tree being walked is not counted here. On a
 * snapshot, what the probe recorded for the link (configTrees) decides —
 * and past the probe's record bound (skillLinksTruncated) a link with
 * nothing under it is not verified.
 */
export async function linkCap(fs: FSProvider, root: string): Promise<(link: string) => Promise<LinkCapReason | undefined>> {
  if (fs.kind === 'snapshot') {
    const records = fs as { skillLinksTruncated?(): boolean; holdsUnder?(dir: string): boolean };
    const truncated = records.skillLinksTruncated?.() ?? false;
    return async link => {
      if (!isAbsolute(link)) return undefined;
      const p = clean(posix.normalize(link));
      const status = configTreeStatus(fs, p);
      if (status === 'limit' || status === 'total') return status;
      if (truncated && status === undefined && !records.holdsUnder?.(p)) return 'limit';
      return undefined;
    };
  }
  let plan: Promise<Map<string, LinkVerdict>> | undefined;
  const load = async (): Promise<Map<string, LinkVerdict>> => {
    const me = homedirOf(fs);
    // a tree in no home (a config-set one elsewhere): judged for the scanned user, as the probe judges it for the config's
    const home = (me && isAbsolute(root) ? await homeOfDir(fs, root, [me]) : undefined) ?? me ?? '';
    let byRoot = planCache.get(fs);
    if (!byRoot) planCache.set(fs, (byRoot = new Map()));
    const key = `${clean(home)}\0${clean(root)}`;
    let hit = byRoot.get(key);
    if (!hit) {
      hit = planSkillLinks(fs, root, p => skillTreeAllowed(fs, p, home), real => limitScan(fs, real))
        .catch(() => new Map<string, LinkVerdict>());
      byRoot.set(key, hit);
    }
    return hit;
  };
  return async link => {
    if (!isAbsolute(link)) return undefined;
    plan ??= load();
    let real: string;
    try {
      real = await fs.realpath(link);
    } catch {
      return undefined;
    }
    const verdict = (await plan).get(real) ?? ((await overEntryLimit(fs, real)) ? 'limit' : 'follow');
    return verdict === 'follow' ? undefined : verdict;
  };
}

/** A component of `p` below `stat` (`p` itself included) is a link (probe throughLink). */
async function throughLink(fs: FSProvider, stat: string, p: string): Promise<boolean> {
  const rel = relative(stat, p);
  if (rel === '' || relEscapes(rel) || isAbsolute(rel)) return false;
  let cur = stat;
  for (const part of rel.split('/')) {
    cur = join(cur, part);
    try {
      await fs.readlink(cur);
      return true;
    } catch {
      // not a link
    }
  }
  return false;
}

/**
 * For an agent's own skills directory `dir` in `home` (one the manifest's
 * skills globs walk): the directory the remote probe walks it under as a
 * config-derived tree, with that tree's entry limit — or undefined when it
 * walks it as an ordinary manifest tree. As the probe does
 * (probe/config_roots.go): a glob's static base that a link takes out of the
 * home (or where no tree is walked) is one (linkedOutSkillBase); otherwise a
 * match of the glob's directory reached through a link below its static
 * part is one (collectLinkedSkillBases) — `~/.claude/skills` itself a link,
 * a PicoClaw `workspace-<id>` linked elsewhere. The deepest such base above
 * `dir` decides, as the CLI reads a snapshot (linkedGap). A plain directory
 * in the home is no such tree: it is walked whatever it holds.
 */
async function linkedManifestBase(fs: FSProvider, dir: string, home: string): Promise<string | undefined> {
  const chain = pathChain(dir);
  let best: string | undefined;
  const consider = (b: string) => {
    if (chain.includes(b) && (best === undefined || b.length > best.length)) best = b;
  };
  for (const g of manifestSkillGlobs()) {
    const exp = expandManifestGlob(fs, g, clean(home));
    if (!exp) continue;
    const baseTail = exp.tail.slice(0, -3); // without `/**`
    const re = expandedGlobRegex(exp.prefix, baseTail);
    const m = re && chain.find(d => re.test(d));
    if (!m) continue;
    // the static part of the glob (doublestar.SplitPattern), home written literally
    const globBase = clean(exp.prefix + splitGlob(exp.tail).base.replace(/^\.$/, ''));
    if (strictlyWithin(globBase, clean(home)) && classifySensitivePath(globBase).length === 0) {
      const stays = strictlyWithin(await resolveExisting(fs, globBase), await resolveExisting(fs, clean(home)))
        && (await skillTreeAllowed(fs, globBase, home));
      if (!stays) {
        consider(globBase);
        continue;
      }
    }
    const split = splitGlob(exp.prefix + baseTail);
    if (split.rest !== '' && (await throughLink(fs, clean(split.base), m))) consider(m);
  }
  return best;
}

/**
 * The scanned home `dir` lies in — the longest one, as written, else once
 * resolved — or undefined (probe/config_roots.go homeOf).
 */
export async function homeOfDir(fs: FSProvider, dir: string, homes: readonly string[]): Promise<string | undefined> {
  if (!isAbsolute(dir)) return undefined;
  const p = normalize(dir);
  const written = homes.filter(h => isAbsolute(h) && strictlyWithin(p, clean(h))).sort((a, b) => b.length - a.length);
  if (written.length > 0) return written[0];
  const real = await resolveExisting(fs, p);
  let best: string | undefined;
  for (const h of homes) {
    if (!isAbsolute(h) || !strictlyWithin(real, await resolveExisting(fs, clean(h)))) continue;
    if (!best || h.length > best.length) best = h;
  }
  return best;
}

/** probe/explicit_links.go maxExplicitLinkHops. */
const MAX_LINK_HOPS = 40;

/**
 * Where the links of `p` lead, read link by link as the probe records them
 * for a refused tree (recordLinkChain): `p` itself and its directories
 * strictly below a home, then the same along each target — never the OS's
 * own links above a home (/etc → /private/etc), so local and remote scans
 * name the same target.
 */
async function linkChainTarget(fs: FSProvider, p: string, homes: readonly string[]): Promise<string> {
  const pending = [clean(p)];
  const seen = new Set<string>();
  let last = clean(p);
  for (let hops = 0; pending.length > 0 && hops < MAX_LINK_HOPS; hops++) {
    const cur = pending.shift()!;
    last = cur;
    const candidates: string[] = [];
    for (let dir = dirname(cur); dir !== dirname(dir); dir = dirname(dir)) {
      if (homes.some(h => strictlyWithin(dir, clean(h)))) candidates.unshift(dir);
    }
    candidates.push(cur);
    for (const comp of candidates) {
      if (seen.has(comp)) continue;
      seen.add(comp);
      let target: string;
      try {
        target = await fs.readlink(comp);
      } catch {
        continue;
      }
      const abs = isAbsolute(target) ? target : join(dirname(comp), target);
      pending.push(clean(join(abs, relative(comp, cur))));
      break;
    }
  }
  return last;
}

/** OS directories whose stored name isn't lower case (macOS). */
const CANONICAL_PLACES: Readonly<Record<string, string>> = { '/system': '/System', '/library': '/Library' };

/**
 * An OS directory label's place (`/system`, lower case) spelled as the OS
 * stores it (`/System`, `/var`) — whatever case the path was written in
 * (`/Private/Var/Folders` is in /var), so every report names it alike.
 */
function canonicalPlace(place: string): string {
  return CANONICAL_PLACES[place] ?? place;
}

/** What a label says, for a report. */
function labelPhrase(label: string): string {
  if (label === 'root') return 'the filesystem root';
  if (label === 'home') return 'the home directory or a directory above it';
  if (label.startsWith('other-home:')) return `another user's home (${label.slice('other-home:'.length)})`;
  if (label.startsWith('system:')) return `an OS directory (${canonicalPlace(label.slice('system:'.length))})`;
  const sink = SENSITIVE_SINKS[Number(label.slice('sink:'.length))];
  return `a credential store or sensitive location (${sink?.label ?? 'credentials'})`;
}

const LABEL_ORDER = ['root', 'home', 'other-home:', 'system:', 'sink:'];

/**
 * For a directory not scanned because of where it is: the target its links
 * lead to (when it is, or lies under, a link) and the kind of place that is
 * — judged from the path as written and as its links spell it, which local
 * and remote scans read alike.
 */
async function refusalDetails(fs: FSProvider, dir: string, home: string, reason: UnscannedSkillsDir['reason']): Promise<Pick<UnscannedSkillsDir, 'target' | 'refusedAs'>> {
  if (!isAbsolute(dir) || !isAbsolute(home)) return {};
  const me = homedirOf(fs);
  const homes = [...new Set([clean(home), ...(me ? [clean(me)] : [])])];
  const target = await linkChainTarget(fs, dir, homes);
  const own = [clean(home)];
  const all = homes;
  const labels = [...new Set([...scopeLabels(dir, own, all), ...(target !== clean(dir) ? scopeLabels(target, own, all) : [])])];
  const first = LABEL_ORDER.map(prefix => labels.filter(l => l === prefix || l.startsWith(prefix)).sort()[0]).find(l => l !== undefined);
  return {
    ...(target !== clean(dir) ? { target } : {}),
    ...(first !== undefined && reason === 'outside' ? { refusedAs: labelPhrase(first) } : {}),
  };
}

/**
 * An unscanned skills directory with what reports say about it: for one
 * refused (`home`, `outside`), the link target and the kind of place. An
 * agent's own default directory is marked so (never "set" by a config).
 */
export async function unscannedDir(
  fs: FSProvider,
  path: string,
  reason: UnscannedSkillsDir['reason'],
  home: string,
  agentDefault = false,
): Promise<UnscannedSkillsDir> {
  const details = reason === 'home' || reason === 'outside' ? await refusalDetails(fs, path, home, reason) : {};
  return { path, reason, ...details, ...(agentDefault ? { agentDefault: true as const } : {}) };
}

/**
 * A skill linked (in a skills tree) to where no skills tree is walked, as an
 * unscanned directory: the home itself, or a place refused (`outside`).
 */
export async function refusedSkillLink(fs: FSProvider, link: string, home: string): Promise<UnscannedSkillsDir> {
  const reason = (await isHomeItself(fs, link, home)) ? 'home' : 'outside';
  return { ...(await unscannedDir(fs, link, reason, home)), skillLink: true };
}

/**
 * Split config-set skills directories into those to scan and those that are
 * not scanned (with the reason). `relative` are values the agent resolves
 * against its own working directory, which neither scan can know.
 */
export async function screenSkillRoots(
  fs: FSProvider,
  roots: readonly string[],
  home: string,
  relativeValues: readonly string[] = [],
): Promise<{ scan: string[]; unscanned: UnscannedSkillsDir[] }> {
  const scan: string[] = [];
  const unscanned: UnscannedSkillsDir[] = relativeValues.map(path => ({ path, reason: 'relative' as const }));
  for (const root of [...new Set(roots.map(cleanSkillRoot))]) {
    const reason = await skillRootGap(fs, root, home);
    if (reason) unscanned.push(await unscannedDir(fs, root, reason, home));
    else scan.push(root);
  }
  return { scan, unscanned };
}

/** The generic kind of place no skills tree is walked. */
const REFUSED_PLACES = 'an OS directory, another user\'s home or a credential store';

/** What an unscanned entry is: a skills directory, or a skill linked into one. */
function unscannedWhat(u: Partial<UnscannedSkillsDir> | undefined): string {
  return u?.skillLink ? 'skill' : 'skills directory';
}

/** Where an unscanned directory is, in a few words: "links to /etc, an OS directory (/etc)". */
function refusedWhere(u: Partial<UnscannedSkillsDir> | undefined, itself: string): string {
  if (u?.target) return `links to ${u.target}, ${itself}`;
  return `${u?.agentDefault ? 'is' : 'set to'} ${itself}`;
}

/**
 * What to do about a directory refused for where it is: audit another user's
 * skills (or ones in a place not named) with `vaso skill audit`; an OS
 * directory, the filesystem root or a credential store is no place for
 * skills at all.
 */
function outsideAdvice(u: Partial<UnscannedSkillsDir> | undefined, path: string): string {
  const as = u?.refusedAs;
  if (as === undefined || as.startsWith('another user\'s home')) return `review it with \`vaso skill audit ${u?.target ?? path}\``;
  return 'keep skills in a dedicated folder';
}

/** The sentence reports and the inventory give for an unscanned skills directory. */
export function unscannedReason(reason: UnscannedSkillsDir['reason'], path = '<path>', u?: Partial<UnscannedSkillsDir>): string {
  switch (reason) {
    case 'home':
      return `not scanned: ${unscannedWhat(u)} ${refusedWhere(u, 'the home directory itself')} — VASO doesn't walk the whole home (locally or remotely); point it at a dedicated folder`;
    case 'outside':
      return `not scanned: ${unscannedWhat(u)} ${refusedWhere(u, u?.refusedAs ?? REFUSED_PLACES)} — VASO doesn't walk it (locally or remotely); ${outsideAdvice(u, path)}`;
    case 'limit':
      return `not scanned: skills directory holds more than ${MAX_SKILL_TREE_ENTRIES} entries, over the limit VASO walks in a skills tree (locally or remotely) — not verified; review it with \`vaso skill audit ${path}\``;
    case 'total':
      return `not scanned: linked skills directory past the ${MAX_LINKED_SKILL_ENTRIES}-entry total VASO walks through the links of one skills tree (locally or remotely) — not verified; review it with \`vaso skill audit ${path}\``;
    case 'relative':
      return 'not scanned: skills directory set as a relative path, which the agent resolves against its working directory — not verified; set an absolute path';
  }
}

/**
 * An unscanned skills directory refused for where it is (outside, the home)
 * that isn't a directory at all — missing, or a link to /dev/null. A
 * snapshot answers only for one the probe judged (it records the mode of a
 * tree it refused when there is one); otherwise it may exist unseen.
 */
export async function unscannedRootMissing(fs: FSProvider, root: UnscannedSkillsDir): Promise<boolean> {
  if (root.reason !== 'outside' && root.reason !== 'home') return false;
  if (fs.kind === 'snapshot' && configTreeStatus(fs, root.path) === undefined && configTreeGap(fs, root.path) === undefined) return false;
  // a snapshot keys paths normalized (`~/./a/../x` is `~/x` there)
  const at = fs.kind === 'snapshot' && isAbsolute(root.path) ? posix.normalize(root.path) : root.path;
  return !(await fs.stat(at).then(st => st.isDirectory(), () => false));
}

/** The sentence for an unscanned directory that isn't one (unscannedRootMissing): SKL-002 and the inventory. */
export function missingRootReason(u: UnscannedSkillsDir): string {
  return `not scanned: ${unscannedWhat(u)} ${u.path} (${unscannedShortReason(u)}) does not exist as a directory — nothing to scan`;
}

/** Why a skills directory went unscanned, in a few words. */
export function unscannedShortReason(u: Pick<UnscannedSkillsDir, 'reason'> & Partial<UnscannedSkillsDir>): string {
  switch (u.reason) {
    case 'home': return u.target ? `links to ${u.target}, the home directory itself` : 'the home directory itself';
    case 'outside': return u.target ? `links to ${u.target}, ${u.refusedAs ?? REFUSED_PLACES}` : (u.refusedAs ?? REFUSED_PLACES);
    case 'limit': return `over the ${MAX_SKILL_TREE_ENTRIES}-entry limit`;
    case 'total': return `past the ${MAX_LINKED_SKILL_ENTRIES}-entry total for linked trees`;
    case 'relative': return 'set as a relative path';
  }
}
