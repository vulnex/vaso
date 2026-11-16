import { join, relative } from 'node:path';
import type { DirentInfo, FSProvider } from './fs-provider.js';
import { relEscapes } from './path-rel.js';
import { isVendorDirName } from './utils.js';

/**
 * Entries one config-derived skills tree may hold before no scan walks it
 * (probe/config_roots.go maxConfigTreeEntries): a config — or a link — that
 * points a skills directory at /Applications or a package store would
 * otherwise have every skill check read the whole of it. Local and remote
 * scans apply the same limit, decided before anything of the tree is read.
 * Each directory link in a skills tree is held to it on its own.
 */
export const MAX_SKILL_TREE_ENTRIES = 10000;

/**
 * What the directory links of one skills tree may hold together
 * (probe/config_roots.go maxLinkedTreeEntries): five trees at the entry
 * limit. Twenty links to 9,999-entry trees made a 49 MB snapshot in 161 s;
 * 50,000 entries keep that near 12 MB, while real linked skill sets (a
 * checkout of a skills repo, a home-manager profile) hold a few thousand.
 */
export const MAX_LINKED_SKILL_ENTRIES = 5 * MAX_SKILL_TREE_ENTRIES;

/**
 * What judging the directory links of one skills tree may count in all
 * (probe/config_roots.go maxJudgedLinkEntries): each distinct target is
 * counted once, to the entry limit, whether it is followed or not — fifty
 * targets at the limit. Past it, a link to a target not yet counted is not
 * counted and gets the links' total verdict: links to many distinct large
 * directories can't make a scan count without end.
 */
export const MAX_JUDGED_LINK_ENTRIES = 10 * MAX_LINKED_SKILL_ENTRIES;

/** probe/collector.go maxLinkDepth (and MAX_LINK_DEPTH in skill-walk.ts). */
const MAX_LINK_DEPTH = 8;

function within(p: string, dir: string): boolean {
  const rel = relative(dir, p);
  return rel === '' || !relEscapes(rel);
}

/** Byte order of the UTF-8 names, as Go sorts a directory listing. */
function byName(a: DirentInfo, b: DirentInfo): number {
  return Buffer.compare(Buffer.from(a.name), Buffer.from(b.name));
}

/** What a count of one tree found: its entries and, in walk order, its links. */
export interface TreeScan {
  n: number;
  /** The tree's symlinks, as paths under its real path. */
  links: string[];
}

/**
 * The entries a walk of the skills tree at `dir` visits, counted as the
 * probe counts them (scanTree in probe/config_roots.go): from where `dir`
 * leads, vendor and VCS directories skipped (build output counted), a link
 * counted as one entry and never descended into — each link is judged from
 * its own target (planSkillLinks) — stopping once past `limit` (Infinity:
 * none). Unlistable directories count as their own entry only. Lists the
 * tree's links in the order Go's WalkDir meets them.
 */
export async function scanSkillTree(fs: FSProvider, dir: string, limit: number): Promise<TreeScan> {
  const s: TreeScan = { n: 0, links: [] };
  let rootReal: string;
  try {
    rootReal = await fs.realpath(dir);
  } catch {
    rootReal = dir;
  }
  const list = async (d: string): Promise<DirentInfo[]> => {
    try {
      return (await fs.readdirEntries(d)).sort(byName);
    } catch {
      return [];
    }
  };
  // Pre-order and depth-first like WalkDir, on an explicit stack
  const stack: Array<{ dir: string; entries: DirentInfo[]; i: number }> = [{ dir: rootReal, entries: await list(rootReal), i: 0 }];
  while (stack.length > 0) {
    const top = stack[stack.length - 1];
    if (top.i >= top.entries.length) {
      stack.pop();
      continue;
    }
    const e = top.entries[top.i++];
    if (e.isDirectory && !e.isSymbolicLink && isVendorDirName(e.name)) continue;
    if (++s.n > limit) return s;
    const p = join(top.dir, e.name);
    if (e.isSymbolicLink) s.links.push(p);
    else if (e.isDirectory) stack.push({ dir: p, entries: await list(p), i: 0 });
  }
  return s;
}

/** scanSkillTree's count. */
export async function countSkillTreeEntries(fs: FSProvider, dir: string, limit: number): Promise<number> {
  return (await scanSkillTree(fs, dir, limit)).n;
}

/** planSkillLinks' verdict on a directory link's target. */
export type LinkVerdict = 'follow' | 'limit' | 'total';

/**
 * Which directory links a walk of the skills tree at `root` follows, by
 * where they lead (real path → verdict) — the same whichever way a walk
 * meets them (probe/config_roots.go linkPlan). Links are taken in WalkDir
 * order from the root, each followed one's own links right after it, at
 * most MAX_LINK_DEPTH deep; one into a tree already taken, back into the
 * root or above it, or where `followLink` refuses, gets no verdict. Each
 * target is counted on its own (`scanOf`, to the entry limit): over
 * MAX_SKILL_TREE_ENTRIES → limit (never walked, so not charged to the
 * total); else its count is charged to the root's links' total, past
 * MAX_LINKED_SKILL_ENTRIES in all → total (not charged either), else
 * follow. Once the targets counted hold MAX_JUDGED_LINK_ENTRIES, a new
 * target is not counted and gets total.
 */
export async function planSkillLinks(
  fs: FSProvider,
  root: string,
  followLink: (path: string) => Promise<boolean>,
  scanOf: (real: string) => Promise<TreeScan>,
): Promise<Map<string, LinkVerdict>> {
  const plan = new Map<string, LinkVerdict>();
  let rootReal: string;
  try {
    rootReal = await fs.realpath(root);
  } catch {
    rootReal = root;
  }
  const taken = [rootReal];
  let used = 0;
  let judged = 0;
  const visit = async (links: readonly string[], depth: number): Promise<void> => {
    if (depth >= MAX_LINK_DEPTH) return;
    for (const p of links) {
      let real: string;
      try {
        real = await fs.realpath(p);
      } catch {
        continue;
      }
      if (plan.has(real) || within(rootReal, real) || taken.some(t => within(real, t))) continue;
      if (!(await followLink(p))) continue;
      try {
        if (!(await fs.stat(real)).isDirectory()) continue;
      } catch {
        continue;
      }
      if (judged >= MAX_JUDGED_LINK_ENTRIES) {
        plan.set(real, 'total');
        continue;
      }
      const s = await scanOf(real);
      judged += s.n;
      if (s.n > MAX_SKILL_TREE_ENTRIES) {
        plan.set(real, 'limit');
      } else if (used + s.n > MAX_LINKED_SKILL_ENTRIES) {
        plan.set(real, 'total');
      } else {
        used += s.n;
        plan.set(real, 'follow');
        taken.push(real);
        await visit(s.links, depth + 1);
      }
    }
  };
  await visit((await scanSkillTree(fs, rootReal, Infinity)).links, 0);
  return plan;
}
