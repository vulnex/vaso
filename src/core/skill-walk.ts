import { basename, dirname, join, normalize, relative, isAbsolute } from 'node:path';
import type { DirentInfo, FSProvider } from './fs-provider.js';
import { relEscapes } from './path-rel.js';
import { classifySensitivePath } from '../analyzers/sensitive-paths.js';
import { linkCap, linkScope } from './skill-root-scope.js';
import type { LinkCapReason } from './skill-root-scope.js';
import { hardLinkedSink } from './hard-link-sinks.js';

/**
 * Skills are often installed as symlinks — `~/.codex/skills/<name>` pointing
 * into a checkout elsewhere. The agent loads what the link points to, so a
 * skill walk must read it too. A plain recursive readdir lists the link and
 * stops there; this walk follows links whose target lies outside the tree
 * (a link back into the tree is already walked), and reports what it finds
 * under the link's path — the path the agent uses.
 *
 * Bounded: each real directory is walked once (cycles, two links to one
 * target) and at most MAX_LINK_DEPTH links deep. The remote probe follows
 * the same links (≥ 1.2.1), so snapshot scans see the same files.
 *
 * A link into a credential store or shell startup file (`skills/keys` →
 * ~/.ssh, `creds.txt` → ~/.aws/credentials) is never followed: SKL-013
 * reports it from its target, and the probe never ships what is behind it
 * (≥ 1.4.0, escapesToSink in probe/sensitive_sinks.go). Nor is one leading
 * where the tree's root may not (another user's home, an OS directory, the
 * home itself — linkScope in skill-root-scope.ts; linkInScope in the probe):
 * walkSkillTree lists those links (`refused`), whose skills go unscanned.
 *
 * A directory link whose target tree holds more than MAX_SKILL_TREE_ENTRIES
 * entries (counted from the target, each link on its own — linkCap) is not
 * followed either, as the probe doesn't (≥ 1.4.2): `/opt/homebrew/Cellar`
 * linked into a plain `~/.claude/skills` would otherwise be read whole. Nor
 * is one past what a tree's links may hold together (MAX_LINKED_SKILL_ENTRIES).
 * walkSkillTree lists those links (`overLimit`, `overTotal`); `vaso skill
 * audit` walks its explicit target whole (`uncapped`).
 */
const MAX_LINK_DEPTH = 8;

function isWithin(path: string, dir: string): boolean {
  const rel = relative(dir, path);
  return rel === '' || !relEscapes(rel);
}

/**
 * Real directories already walked. Lookups go up the path (ancestors) or use
 * an index of descendants, never over the whole set: scanning every visited
 * path per link made a tree of thousands of linked skills quadratic.
 */
class Visited {
  private readonly paths = new Set<string>();
  /** ancestor → visited paths strictly below it */
  private readonly below = new Map<string, string[]>();

  constructor(first: string) {
    this.add(first);
  }

  has(path: string): boolean {
    return this.paths.has(path);
  }

  add(path: string): void {
    if (this.paths.has(path)) return;
    this.paths.add(path);
    for (let a = dirname(path); ; a = dirname(a)) {
      const list = this.below.get(a);
      if (list) list.push(path);
      else this.below.set(a, [path]);
      if (dirname(a) === a) break;
    }
  }

  /** `path` or a directory above it has been walked. */
  covers(path: string): boolean {
    for (let p = path; ; p = dirname(p)) {
      if (this.paths.has(p)) return true;
      if (dirname(p) === p) return false;
    }
  }

  /** Walked paths strictly inside `dir`. */
  inside(dir: string): string[] {
    return this.below.get(dir) ?? [];
  }
}

/** Some directory from `path` up to (not including) `stop` is in `set`. */
function underAny(path: string, stop: string, set: Set<string>): boolean {
  for (let p = path; p !== stop && dirname(p) !== p; p = dirname(p)) {
    if (set.has(p)) return true;
  }
  return false;
}

async function realOrSelf(fs: FSProvider, path: string): Promise<string> {
  try {
    return await fs.realpath(path);
  } catch {
    return path;
  }
}

/**
 * The link's target — resolved, or as written (macOS resolves /etc to
 * /private/etc) — is a sensitive location (SENSITIVE_SINKS) that the walked
 * root itself does not name.
 */
async function sinkLink(fs: FSProvider, link: string, real: string, named: ReadonlySet<string>): Promise<boolean> {
  const targets = [real];
  if (typeof fs.readlink === 'function') {
    try {
      const raw = await fs.readlink(link);
      targets.push(isAbsolute(raw) ? normalize(raw) : join(dirname(link), raw));
    } catch {
      // target as resolved is enough
    }
  }
  return targets.some(t => classifySensitivePath(t).some(label => !named.has(label)));
}

/**
 * Every entry under `root`, recursively, plus the contents of symlinked files
 * and directories that point outside it. A followed directory link appears as
 * a directory entry; a followed file link as a file entry. Throws like
 * readdirEntries when `root` itself can't be listed.
 */
export async function walkSkillTree(fs: FSProvider, root: string, refused?: string[], opts: SkillWalkOptions = {}): Promise<DirentInfo[]> {
  const real = await realOrSelf(fs, root);
  const rules: WalkRules = {
    inScope: noting(await linkScope(fs, root), refused),
    capped: notingCap(await capOf(fs, root, opts), opts),
  };
  return walk(fs, root, [real], new Visited(real), 0, true, new Set(classifySensitivePath(root)), rules);
}

export interface SkillWalkOptions {
  /** Directory links left out for the size of the tree they lead to (linkCap) are added here. */
  overLimit?: string[];
  /** Directory links left out past what the tree's links may hold together (linkCap) are added here. */
  overTotal?: string[];
  /** Directory links a snapshot's probe left out after it stopped recording such links (linkCap) are added here. */
  unrecorded?: string[];
  /** Follow links whatever the size of their tree (`vaso skill audit`'s explicit target). */
  uncapped?: boolean;
}

/** The size rule for a walk of `root` (linkCap), or none when uncapped. */
async function capOf(fs: FSProvider, root: string, opts: SkillWalkOptions): Promise<CapRule> {
  return opts.uncapped ? async () => undefined : linkCap(fs, root);
}

/** `rule`, adding every link it refuses to `list` (when given). */
function noting(rule: LinkRule, list: string[] | undefined): LinkRule {
  if (!list) return rule;
  return async (link: string) => {
    const answer = await rule(link);
    if (!answer && !list.includes(link)) list.push(link);
    return answer;
  };
}

/** `rule`, adding every link it leaves out to opts' list for the reason. */
function notingCap(rule: CapRule, opts: SkillWalkOptions): CapRule {
  return async (link: string) => {
    const reason = await rule(link);
    const list = reason === 'limit' ? opts.overLimit : reason === 'total' ? opts.overTotal : reason === 'truncated' ? opts.unrecorded : undefined;
    if (list && !list.includes(link)) list.push(link);
    return reason;
  };
}

/** Why a directory link met in the walk is left out for its size, if it is. */
type CapRule = (link: string) => Promise<LinkCapReason | undefined>;

/** A yes/no rule on a link met in the walk. */
type LinkRule = (link: string) => Promise<boolean>;

interface WalkRules {
  /** The link may be followed for where it leads (linkScope). */
  inScope: LinkRule;
  /** The directory link is left out for the size of what it leads to (linkCap). */
  capped: CapRule;
}

/**
 * The second half of walkSkillTree for a caller that already listed `root`
 * recursively: what the symlinks among `entries` (those inside `root`) lead
 * to. Entries of the listing itself are not repeated.
 */
export async function followSkillLinks(fs: FSProvider, root: string, entries: DirentInfo[], opts: SkillWalkOptions = {}): Promise<DirentInfo[]> {
  const rootReal = await realOrSelf(fs, root);
  const visited = new Visited(rootReal);
  const prefix = root.endsWith('/') ? root : root + '/';
  const links = entries.filter(e => e.isSymbolicLink && (e.parentPath === root || (e.parentPath ?? '').startsWith(prefix)));
  const rules: WalkRules = { inScope: await linkScope(fs, root), capped: notingCap(await capOf(fs, root, opts), opts) };
  return (await follow(fs, root, links, [rootReal], visited, 0, new Set(classifySensitivePath(root)), rules)).filter(e => !e.isSymbolicLink || !links.includes(e));
}

async function walk(
  fs: FSProvider,
  dir: string,
  roots: string[],
  visited: Visited,
  depth: number,
  isRoot: boolean,
  named: ReadonlySet<string>,
  rules: WalkRules,
): Promise<DirentInfo[]> {
  let entries: DirentInfo[];
  try {
    entries = await fs.readdirEntries(dir, { recursive: true });
  } catch (err) {
    if (isRoot) throw err;
    return [];
  }
  if (!isRoot) {
    // Parts of this target already walked through a more specific link
    // (`ext-skill` → ~/dev/ext-skill before `chain/devlink` → ~/dev)
    const real = roots[roots.length - 1];
    const taken = new Set(visited.inside(real));
    if (taken.size > 0) {
      entries = entries.filter(e => !underAny(join(real, relative(dir, e.parentPath ?? dir), e.name), real, taken));
    }
  }
  entries = entries.filter(e => !inSinkByTarget(dir, roots[roots.length - 1], e, named));
  entries = await withoutHardLinkedSinks(fs, dir, entries, named);
  return follow(fs, dir, entries, roots, visited, depth, named, rules);
}

/**
 * For a caller holding a plain listing of a skills tree (IOC file walks):
 * whether `file`, under `root`, really is in a credential store neither the
 * root nor the file's own spelling names (see inSinkByTarget). Real parent
 * directories are cached in `cache`.
 */
export async function skillFileInSink(fs: FSProvider, root: string, file: string, cache: Map<string, string>): Promise<boolean> {
  const parent = dirname(file);
  let real = cache.get(parent);
  if (real === undefined) {
    real = await realOrSelf(fs, parent);
    cache.set(parent, real);
  }
  const target = join(real, basename(file));
  const named = new Set([...classifySensitivePath(root), ...classifySensitivePath(file)]);
  if (target !== file && classifySensitivePath(target).some(label => !named.has(label))) return true;
  return (await hardLinkedSink(fs, file, named)) !== undefined;
}

/**
 * `entries` without the files that are a credential-store file under another
 * name — a hard link (hard-link-sinks.ts) — to a store neither the walked
 * root nor the file's own spelling names. Never read, as the probe never
 * ships them (hardLinkedSink in probe/hard_links.go).
 */
async function withoutHardLinkedSinks(fs: FSProvider, dir: string, entries: DirentInfo[], named: ReadonlySet<string>): Promise<DirentInfo[]> {
  if (typeof fs.hardLinkOf !== 'function') return entries;
  const drop = new Set<DirentInfo>();
  for (let i = 0; i < entries.length; i += 64) {
    await Promise.all(entries.slice(i, i + 64).map(async e => {
      if (e.isFile && !e.isSymbolicLink && await hardLinkedSink(fs, join(e.parentPath ?? dir, e.name), named) !== undefined) drop.add(e);
    }));
  }
  return drop.size === 0 ? entries : entries.filter(e => !drop.has(e));
}

/**
 * A file listed under `dir` (whose real path is `real`; nothing between them
 * is a link — the listing doesn't follow any) that really is in a credential
 * store neither the walked root nor its own spelling names: a skills dir
 * linked to `~/.claude` lists `.credentials.json`, one linked to `~/.config`
 * lists `gh/hosts.yml`. Never read, as the probe never ships it
 * (resolvedIntoSink in probe/sensitive_sinks.go).
 */
function inSinkByTarget(dir: string, real: string, entry: DirentInfo, named: ReadonlySet<string>): boolean {
  if (!entry.isFile) return false;
  const rel = join(relative(dir, entry.parentPath ?? dir), entry.name);
  const target = join(real, rel);
  const spelled = join(dir, rel);
  if (target === spelled) return false;
  const own = new Set(classifySensitivePath(spelled));
  return classifySensitivePath(target).some(label => !named.has(label) && !own.has(label));
}

/** `entries` with every followable symlink among them expanded in place. */
async function follow(
  fs: FSProvider,
  dir: string,
  entries: DirentInfo[],
  roots: string[],
  visited: Visited,
  depth: number,
  named: ReadonlySet<string>,
  rules: WalkRules,
): Promise<DirentInfo[]> {
  const { inScope } = rules;
  const out: DirentInfo[] = [];
  const dirLinks: Array<{ entry: DirentInfo; parent: string; link: string; real: string }> = [];
  for (const entry of entries) {
    if (!entry.isSymbolicLink) {
      out.push(entry);
      continue;
    }
    const parent = entry.parentPath ?? dir;
    const link = join(parent, entry.name);
    if (depth >= MAX_LINK_DEPTH) {
      out.push(entry);
      continue;
    }
    let real: string;
    try {
      real = await fs.realpath(link);
    } catch {
      out.push(entry); // dangling
      continue;
    }
    // A link up to the home (or above it) is not followed either way; judged
    // still, so a walk that lists refused links names it
    if (roots.some(r => isWithin(r, real) && r !== real)) await inScope(link);
    // Inside a tree already being walked, or a parent of one (a link back up
    // would re-walk it), or seen through another link
    if (roots.some(r => isWithin(real, r) || isWithin(r, real)) || visited.has(real) || await sinkLink(fs, link, real, named)
      || !(await inScope(link))) {
      out.push(entry);
      continue;
    }
    let st;
    try {
      st = await fs.stat(link);
    } catch {
      out.push(entry);
      continue;
    }
    if (st.isFile()) {
      visited.add(real);
      out.push({ name: entry.name, isFile: true, isDirectory: false, parentPath: parent });
    } else if (st.isDirectory()) {
      dirLinks.push({ entry, parent, link, real });
    } else {
      out.push(entry);
    }
  }
  // Deepest target first, so a link to a parent dir (`devlink` → ~/dev) does
  // not report again — under another path — a skill linked in on its own
  // (`ext-skill` → ~/dev/ext-skill): each file is reported once, under the
  // most specific link.
  dirLinks.sort((a, b) => b.real.length - a.real.length);
  for (const { entry, parent, link, real } of dirLinks) {
    // Over the entry limit or the links' total: neither walked nor marked
    // walked (another link to the same tree is reported too)
    if (visited.covers(real) || (await rules.capped(link)) !== undefined) {
      out.push(entry);
      continue;
    }
    visited.add(real);
    out.push({ name: entry.name, isFile: false, isDirectory: true, parentPath: parent });
    out.push(...await walk(fs, link, [...roots, real], visited, depth + 1, false, named, rules));
  }
  return out;
}

/**
 * The skill directories directly inside `skillsDir`, including symlinked
 * ones (any target — the name is what the agent shows and loads).
 */
export async function listSkillDirs(fs: FSProvider, skillsDir: string): Promise<DirentInfo[]> {
  const entries = await fs.readdirEntries(skillsDir);
  const out: DirentInfo[] = [];
  for (const entry of entries) {
    if (entry.isDirectory) {
      out.push(entry);
    } else if (entry.isSymbolicLink) {
      try {
        if ((await fs.stat(join(skillsDir, entry.name))).isDirectory()) {
          out.push({ ...entry, isDirectory: true, isSymbolicLink: true });
        }
      } catch {
        // dangling or not collected
      }
    }
  }
  return out;
}

export interface SkillDir {
  /** Path the agent loads the skill from (a symlinked skill keeps its link path). */
  dir: string;
  /** Directory name. */
  name: string;
}

/**
 * Every skill under `skillsDirs` (symlinked ones included, see listSkillDirs).
 * A skills dir that is itself one skill — it holds a SKILL.md, or it is the
 * target of `vaso skill audit <dir>` (`rootIsSkill`) — counts as a skill too,
 * so its own package.json and metadata are read.
 */
export async function listSkills(
  fs: FSProvider,
  skillsDirs: readonly string[],
  opts: { rootIsSkill?: boolean } = {},
): Promise<SkillDir[]> {
  const out: SkillDir[] = [];
  const seen = new Set<string>();
  const add = (dir: string, name: string) => {
    if (seen.has(dir)) return;
    seen.add(dir);
    out.push({ dir, name });
  };
  for (const root of skillsDirs) {
    if (opts.rootIsSkill || await fs.access(join(root, 'SKILL.md'))) add(root, basename(root));
    let entries: DirentInfo[];
    try {
      entries = await listSkillDirs(fs, root);
    } catch {
      continue;
    }
    for (const entry of entries) add(join(root, entry.name), entry.name);
  }
  return out;
}

/**
 * The `name:` in SKILL.md's YAML frontmatter — the name agents show and
 * invoke the skill by, which need not match its directory name.
 */
export async function skillFrontmatterName(fs: FSProvider, skillDir: string): Promise<string | undefined> {
  let text: string;
  try {
    text = await fs.readFile(join(skillDir, 'SKILL.md'));
  } catch {
    return undefined;
  }
  const fm = /^﻿?---\r?\n([\s\S]*?)\r?\n---/.exec(text);
  if (!fm) return undefined;
  // The bare value is taken greedily to the line end and trimmed: a lazy
  // `[^\n#]*?` before `\s*` retried a long space run from every position
  // (80 KB: 22 s)
  const m = /^name:\s*(?:"([^"\n]*)"|'([^'\n]*)'|([^\n\r\u2028\u2029#]*))\s*(?:#.*)?$/m.exec(fm[1]);
  const name = (m?.[1] ?? m?.[2] ?? m?.[3])?.trim();
  return name || undefined;
}
