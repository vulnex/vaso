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
 */
export const MAX_SKILL_TREE_ENTRIES = 10000;

/** probe/collector.go maxLinkDepth (and MAX_LINK_DEPTH in skill-walk.ts). */
const MAX_LINK_DEPTH = 8;

function within(p: string, dir: string): boolean {
  const rel = relative(dir, p);
  return rel === '' || !relEscapes(rel);
}

/**
 * How many entries a walk of the skills tree at `dir` visits, counted as the
 * probe counts them (countTreeEntries in probe/config_roots.go): from where
 * `dir` leads, vendor and VCS directories skipped (build output counted),
 * directory links followed where `followLink` allows — each real directory
 * once, not back into the tree or above it, at most MAX_LINK_DEPTH deep — and
 * the count stops once past `limit`. Unlistable directories count as their
 * own entry only.
 */
export async function countSkillTreeEntries(
  fs: FSProvider,
  dir: string,
  limit: number,
  followLink: (path: string) => Promise<boolean>,
): Promise<number> {
  let n = 0;
  const visited = new Set<string>();
  let rootReal: string;
  try {
    rootReal = await fs.realpath(dir);
  } catch {
    rootReal = dir;
  }
  visited.add(rootReal);

  /** Walks `root` (its entries, not itself); true once past the limit. */
  const list = async (d: string): Promise<DirentInfo[]> => {
    try {
      // lexical order, as Go's WalkDir: which link reaches a shared target first
      return (await fs.readdirEntries(d)).sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    } catch {
      return [];
    }
  };
  // Pre-order and depth-first like WalkDir, on an explicit stack
  const walk = async (root: string, depth: number): Promise<boolean> => {
    const stack: Array<{ dir: string; entries: DirentInfo[]; i: number }> = [{ dir: root, entries: await list(root), i: 0 }];
    while (stack.length > 0) {
      const top = stack[stack.length - 1];
      if (top.i >= top.entries.length) {
        stack.pop();
        continue;
      }
      const e = top.entries[top.i++];
      if (e.isDirectory && !e.isSymbolicLink && isVendorDirName(e.name)) continue;
      if (++n > limit) return true;
      const p = join(top.dir, e.name);
      if (e.isDirectory && !e.isSymbolicLink) {
        stack.push({ dir: p, entries: await list(p), i: 0 });
        continue;
      }
      if (!e.isSymbolicLink || depth >= MAX_LINK_DEPTH || !(await followLink(p))) continue;
      let real: string;
      try {
        real = await fs.realpath(p);
      } catch {
        continue;
      }
      // a link back into the tree or above it isn't followed
      if (visited.has(real) || within(real, rootReal) || within(rootReal, real)) continue;
      try {
        if (!(await fs.stat(p)).isDirectory()) continue;
      } catch {
        continue;
      }
      visited.add(real);
      if (await walk(real, depth + 1)) return true;
    }
    return false;
  };
  await walk(rootReal, 0);
  return n;
}
