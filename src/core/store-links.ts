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
 * The home holding an agent folder: the scanning user's home for that user's
 * own folder (`ownAgentDir`: ~/.copilot, or the folder COPILOT_HOME names),
 * else the parent of another user's ~/.copilot (`--all-users`). Never the
 * parent of a folder COPILOT_HOME names: with `COPILOT_HOME=~/x/.copilot`
 * and `~/x` linked out of the home, that outside folder would count as a
 * home, and whatever lies behind the link as the agent's own.
 */
export function storeHomeOf(agentDir: string, homedir: string, ownAgentDir: string): string {
  if (agentDir === ownAgentDir) return homedir;
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

/**
 * Why the agent's folder itself (~/.copilot, or the folder COPILOT_HOME
 * names) is a foreign place for its private stores, written at `written` and
 * resolving to `real`: it resolves into a sensitive location; a folder set
 * inside the home resolves out of it (a link on the folder or on one above
 * it); or it resolves to the home or a folder above it. Undefined when its
 * stores are the agent's own: no link, a link within the home, or a folder
 * set outside the home on purpose (COPILOT_HOME=/data/copilot) — wherever
 * that leads, it is the place the user chose. The Go port is foreignAgentDir
 * in probe/store_links.go (rows with `agentDir` in store-link-cases.json).
 */
export function foreignAgentDir(written: string, real: string, homeRoots: string[]): ForeignReason | undefined {
  const label = classifySensitivePath(real)[0];
  if (label) return { why: 'sensitive', label };
  if (real === written) return undefined;
  if (homeRoots.some(root => withinDir(written, root)) && !homeRoots.some(root => withinDir(real, root))) return { why: 'outside' };
  if (homeRoots.some(root => withinDir(root, real))) return { why: 'home' };
  return undefined;
}
