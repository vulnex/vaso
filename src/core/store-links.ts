import { basename, dirname, isAbsolute, relative } from 'node:path';
import { classifySensitivePath } from '../analyzers/sensitive-paths.js';

/**
 * Why a folder linked from a private store (Copilot's session-state/, or a
 * folder inside one) is not the agent's own: it lands in a sensitive location,
 * leaves the home and the agent's folder, is the home (or a folder above it),
 * or holds the store. GHC-001 reports such a link once and never walks it; the
 * probe records only the link (privateStores in the manifest) and nothing
 * behind it. The Go port is foreignStoreTarget in probe/store_links.go — both
 * sides read probe/testdata/store-link-cases.json.
 */
export type ForeignReason =
  | { why: 'sensitive'; label: string }
  | { why: 'outside' | 'home' | 'store' };

export interface StorePlaces {
  /** The home holding the agent's folder, each spelling (as written, resolved). */
  homeRoots: string[];
  /** The agent's folder (~/.copilot), each spelling. */
  storeRoots: string[];
  /** The store folder the link is in, or is (~/.copilot/session-state). */
  storeDir: string;
}

/**
 * The home holding an agent folder: the parent of ~/.copilot, else (a folder
 * COPILOT_HOME moved elsewhere) the scanning user's home.
 */
export function storeHomeOf(agentDir: string, homedir: string): string {
  return basename(agentDir) === '.copilot' ? dirname(agentDir) : homedir;
}

/** Whether `path` is `dir` or inside it. */
export function withinDir(path: string, dir: string): boolean {
  const rel = relative(dir, path);
  return rel === '' || (!rel.startsWith('..') && !isAbsolute(rel));
}

/** Why a linked folder resolving to `target` is foreign; undefined for an ordinary folder of the home. */
export function foreignStoreTarget(target: string, places: StorePlaces): ForeignReason | undefined {
  const { homeRoots, storeRoots, storeDir } = places;
  const label = classifySensitivePath(target)[0];
  if (label) return { why: 'sensitive', label };
  if (![...homeRoots, ...storeRoots].some(root => withinDir(target, root))) return { why: 'outside' };
  if (homeRoots.some(root => withinDir(root, target))) return { why: 'home' };
  if (storeRoots.some(root => withinDir(root, target)) || withinDir(storeDir, target)) return { why: 'store' };
  return undefined;
}
