import { join, relative, isAbsolute } from 'node:path';
import type { DirentInfo, FSProvider } from './fs-provider.js';

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
 */
const MAX_LINK_DEPTH = 8;

function isWithin(path: string, dir: string): boolean {
  const rel = relative(dir, path);
  return rel === '' || (!rel.startsWith('..') && !isAbsolute(rel));
}

async function realOrSelf(fs: FSProvider, path: string): Promise<string> {
  try {
    return await fs.realpath(path);
  } catch {
    return path;
  }
}

/**
 * Every entry under `root`, recursively, plus the contents of symlinked files
 * and directories that point outside it. A followed directory link appears as
 * a directory entry; a followed file link as a file entry. Throws like
 * readdirEntries when `root` itself can't be listed.
 */
export async function walkSkillTree(fs: FSProvider, root: string): Promise<DirentInfo[]> {
  const visited = new Set<string>([await realOrSelf(fs, root)]);
  return walk(fs, root, [...visited], visited, 0, true);
}

/**
 * The second half of walkSkillTree for a caller that already listed `root`
 * recursively: what the symlinks among `entries` (those inside `root`) lead
 * to. Entries of the listing itself are not repeated.
 */
export async function followSkillLinks(fs: FSProvider, root: string, entries: DirentInfo[]): Promise<DirentInfo[]> {
  const rootReal = await realOrSelf(fs, root);
  const visited = new Set<string>([rootReal]);
  const prefix = root.endsWith('/') ? root : root + '/';
  const links = entries.filter(e => e.isSymbolicLink && (e.parentPath === root || (e.parentPath ?? '').startsWith(prefix)));
  return (await follow(fs, root, links, [rootReal], visited, 0)).filter(e => !e.isSymbolicLink || !links.includes(e));
}

async function walk(
  fs: FSProvider,
  dir: string,
  roots: string[],
  visited: Set<string>,
  depth: number,
  isRoot: boolean,
): Promise<DirentInfo[]> {
  let entries: DirentInfo[];
  try {
    entries = await fs.readdirEntries(dir, { recursive: true });
  } catch (err) {
    if (isRoot) throw err;
    return [];
  }
  return follow(fs, dir, entries, roots, visited, depth);
}

/** `entries` with every followable symlink among them expanded in place. */
async function follow(
  fs: FSProvider,
  dir: string,
  entries: DirentInfo[],
  roots: string[],
  visited: Set<string>,
  depth: number,
): Promise<DirentInfo[]> {
  const out: DirentInfo[] = [];
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
    // Inside a tree already being walked, or a parent of one (a link back up
    // would re-walk it), or seen through another link
    if (roots.some(r => isWithin(real, r) || isWithin(r, real)) || visited.has(real)) {
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
      out.push({ name: entry.name, isFile: true, isDirectory: false, parentPath: parent });
    } else if (st.isDirectory()) {
      visited.add(real);
      out.push({ name: entry.name, isFile: false, isDirectory: true, parentPath: parent });
      out.push(...await walk(fs, link, [...roots, real], visited, depth + 1, false));
    } else {
      out.push(entry);
    }
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
