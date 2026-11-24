import { readdir, lstat, stat } from 'node:fs/promises';
import { isAbsolute, join, normalize } from 'node:path';
import { classifySensitivePath } from '../analyzers/sensitive-paths.js';
import type { FSProvider } from './fs-provider.js';

/**
 * A hard link has no target to resolve: a skills-tree file hard-linked to
 * ~/.ssh/id_rsa is, to every path check, a plain file in the skills tree.
 * Only its identity (device and inode) tells. A regular file with more than
 * one link whose identity is a file in a credential store of the home is
 * judged as a link into that store: never read (local scans) and never
 * shipped (the probe records it `omitted: sensitive` with `hardLinkOf`,
 * probe/hard_links.go), and SKL-013 reports it.
 */

/**
 * Where credential-store files live under a home, searched `depth` levels
 * down (1 = the directory's own entries). A file found there counts only
 * when its path is a sensitive sink (SENSITIVE_SINKS). Mirrors
 * sinkSearchRoots in probe/hard_links.go entry for entry.
 */
export const SINK_SEARCH_ROOTS: ReadonlyArray<{ path: string; depth: number }> = [
  { path: '.', depth: 1 },
  { path: '.ssh', depth: 3 },
  { path: '.aws', depth: 3 },
  { path: '.gnupg', depth: 3 },
  { path: '.kube', depth: 3 },
  { path: '.docker', depth: 2 },
  { path: '.config/gh', depth: 2 },
  { path: '.config/gcloud', depth: 4 },
  { path: '.azure', depth: 3 },
  { path: '.password-store', depth: 6 },
  { path: 'Library/Keychains', depth: 3 },
  { path: '.codex', depth: 1 },
  { path: '.claude', depth: 1 },
  { path: '.gemini', depth: 1 },
  { path: '.qwen', depth: 1 },
  { path: '.local/share/opencode', depth: 1 },
  { path: '.local/share/devin', depth: 1 },
  { path: '.config/nanoclaw', depth: 1 },
  { path: '.hermes', depth: 3 },
  { path: '.openclaw', depth: 5 },
  { path: '.clawdbot', depth: 5 },
  { path: '.nanobot', depth: 4 },
  { path: '.abacusai', depth: 1 },
  { path: '.grokbot', depth: 1 },
  { path: '.cursor/sand', depth: 1 },
  { path: '.ironclaw/reborn', depth: 3 },
  { path: '.zeroclaw', depth: 1 },
  { path: '.config/openshell', depth: 5 },
  { path: '.local/state/openshell', depth: 5 },
  { path: 'Library/Cookies', depth: 1 },
  // stores the 1.4.3 sink list added below the home's top level (dt25
  // g9-F3): shell sessions and histories (zsh's ZDOTDIR conventions too),
  // rclone, terraform, cargo, GNOME keyring
  { path: '.zsh_sessions', depth: 1 },
  { path: '.local/share/fish', depth: 1 },
  { path: '.config/zsh', depth: 1 },
  { path: '.zsh', depth: 1 },
  { path: '.config/rclone', depth: 1 },
  { path: '.terraform.d', depth: 1 },
  { path: '.cargo', depth: 1 },
  { path: '.local/share/keyrings', depth: 2 },
];

/**
 * $ZDOTDIR when it lies inside `home` (zsh keeps .zsh_history there),
 * undefined otherwise. Mirrors zdotdirIn in probe/hard_links.go.
 */
export function zdotdirIn(home: string, env: Record<string, string | undefined> = process.env): string | undefined {
  const z = env.ZDOTDIR;
  if (!z || !isAbsolute(z)) return undefined;
  const clean = normalize(z).replace(/\/+$/, '');
  return clean.startsWith(`${home.replace(/\/+$/, '')}/`) ? clean : undefined;
}

/** Entries read to build one home's index, at most (maxSinkIdentityEntries). */
export const MAX_SINK_IDENTITY_ENTRIES = 20000;

/** Identity → path of every multiply-linked regular file in `home`'s credential stores. */
export async function buildSinkIdentityIndex(home: string): Promise<Map<string, string>> {
  const out = new Map<string, string>();
  const budget = { left: MAX_SINK_IDENTITY_ENTRIES };
  for (const r of SINK_SEARCH_ROOTS) {
    await indexSinkTree(r.path === '.' ? home : join(home, r.path), r.depth, budget, out);
  }
  const zdotdir = zdotdirIn(home);
  if (zdotdir) await indexSinkTree(zdotdir, 1, budget, out);
  return out;
}

async function indexSinkTree(dir: string, depth: number, budget: { left: number }, out: Map<string, string>): Promise<void> {
  if (depth < 1 || budget.left <= 0) return;
  let names: string[];
  try {
    names = await readdir(dir);
  } catch {
    return;
  }
  // the probe reads names in byte order (Go's sort.Strings)
  names.sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)));
  for (const n of names) {
    if (budget.left <= 0) return;
    budget.left--;
    const p = join(dir, n);
    let s;
    try {
      s = await lstat(p, { bigint: true });
    } catch {
      continue;
    }
    if (s.isDirectory()) {
      await indexSinkTree(p, depth - 1, budget, out);
      continue;
    }
    if (!s.isFile() || s.nlink < 2n || classifySensitivePath(p).length === 0) continue;
    const id = `${s.dev}:${s.ino}`;
    if (!out.has(id)) out.set(id, p);
  }
}

/** The user home a path lies in, by location (/home/<u>, /Users/<u>, /root, /var/root). */
export function homeOfPath(path: string): string | undefined {
  const m = /^\/(?:home|Users)\/[^/]+|^\/root(?=\/|$)|^\/var\/root(?=\/|$)/.exec(path);
  return m?.[0];
}

/**
 * Local half of FSProvider.hardLinkOf: the credential-store file (in
 * `homes`' stores) the regular file at `path` is a hard link to, if any.
 */
export class LocalHardLinkIndex {
  private readonly indexes = new Map<string, Promise<Map<string, string>>>();

  constructor(private readonly homes: () => string[]) {}

  async hardLinkOf(path: string): Promise<string | undefined> {
    try {
      return await this.lookup(path);
    } catch {
      return undefined;
    }
  }

  private async lookup(path: string): Promise<string | undefined> {
    const homes = [...this.homes()];
    const own = homeOfPath(path);
    if (own && !homes.includes(own)) homes.push(own);
    const indexes: Array<Map<string, string>> = [];
    for (const h of homes) {
      let index = this.indexes.get(h);
      if (!index) {
        index = buildSinkIdentityIndex(h);
        this.indexes.set(h, index);
      }
      const built = await index;
      if (built.size > 0) indexes.push(built);
    }
    // A hard link to a store file makes that file multiply linked too: with
    // none in the stores (the usual case) no file needs a stat
    if (indexes.length === 0) return undefined;
    const s = await stat(path, { bigint: true });
    if (!s?.isFile() || s.nlink < 2n) return undefined;
    const id = `${s.dev}:${s.ino}`;
    for (const index of indexes) {
      const hit = index.get(id);
      if (hit !== undefined && hit !== path) return hit;
    }
    return undefined;
  }
}

/**
 * The credential-store file `file` is a hard link to, when that store is one
 * neither `file`'s own spelling nor `named` (the walked root's sinks) names
 * — resolvedIntoSink's rule (probe hardLinkedSink); undefined otherwise or
 * when the provider can't tell.
 */
export async function hardLinkedSink(fs: FSProvider, file: string, named: ReadonlySet<string> = new Set()): Promise<string | undefined> {
  if (typeof fs.hardLinkOf !== 'function') return undefined;
  const sink = await fs.hardLinkOf(file);
  if (sink === undefined) return undefined;
  const own = new Set(classifySensitivePath(file));
  return classifySensitivePath(sink).some(label => !named.has(label) && !own.has(label)) ? sink : undefined;
}
