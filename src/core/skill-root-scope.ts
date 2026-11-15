import { basename, dirname, isAbsolute, join, normalize, relative } from 'node:path';
import type { FSProvider } from './fs-provider.js';
import type { UnscannedSkillsDir } from './types.js';
import { classifySensitivePath } from '../analyzers/sensitive-paths.js';
import { configTreeGap, configTreeStatus, manifestCoversTree } from './probe-coverage.js';
import { relEscapes } from './path-rel.js';

/**
 * Skills directories an agent's config sets (an OpenClaw extraDir, a Nanobot
 * or ZeroClaw workspace) are walked only strictly inside the home of the user
 * whose config names them — judged once both are resolved, so either spelling
 * of a linked home is the home — and never in a credential store
 * (SENSITIVE_SINKS), as written or resolved. The remote probe applies the
 * same rule (treeAllowed in probe/config_roots.go), so a config pointing a
 * skill root at `/`, `/etc`, another user's home, the home itself or `~/.ssh`
 * is reported "not scanned" by local and remote scans alike, instead of one
 * walking the whole disk and the other passing it silently.
 *
 * An agent's own default trees (what the probe's manifest walks) are scanned
 * wherever they are — unless one in a home is a link that leaves the home or
 * enters a credential store (`~/.picoclaw/workspace-<id>` → `~/.ssh`): the
 * same rule then, on both sides (refuseLinkedSkillBase in the probe).
 *
 * On a snapshot, what the probe recorded for a tree (configTrees) decides: it
 * judged the real filesystem, whose links a snapshot only partly records.
 */

function strictlyWithin(p: string, dir: string): boolean {
  const rel = relative(dir, p);
  return rel !== '' && !relEscapes(rel) && !isAbsolute(rel);
}

/** `p` resolved like a realpath for as much of it as exists; the rest appended. */
async function resolveExisting(fs: FSProvider, p: string): Promise<string> {
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

/** A config-derived tree may be walked from `dir` (see the module comment). */
export async function inHomeOutsideStores(fs: FSProvider, dir: string, home: string): Promise<boolean> {
  if (!isAbsolute(dir) || !isAbsolute(home)) return false;
  const p = normalize(dir);
  const h = normalize(home).replace(/(.)\/$/, '$1');
  if (h === '/' || classifySensitivePath(p).length > 0) return false;
  const real = await resolveExisting(fs, p);
  const realHome = await resolveExisting(fs, h);
  return realHome !== '/' && strictlyWithin(real, realHome) && classifySensitivePath(real).length === 0;
}

/** `dir` lies strictly inside `home`, as written or once both are resolved. */
export async function withinHome(fs: FSProvider, dir: string, home: string): Promise<boolean> {
  if (!isAbsolute(dir) || !isAbsolute(home)) return false;
  const p = normalize(dir);
  const h = normalize(home).replace(/(.)\/$/, '$1');
  if (strictlyWithin(p, h)) return true;
  return strictlyWithin(await resolveExisting(fs, p), await resolveExisting(fs, h));
}

/** `dir` is the user's home itself, as written or once resolved. */
async function isHomeItself(fs: FSProvider, dir: string, home: string): Promise<boolean> {
  if (!isAbsolute(dir) || !isAbsolute(home)) return false;
  const trim = (x: string): string => normalize(x).replace(/(.)\/$/, '$1');
  if (trim(dir) === trim(home)) return true;
  return trim(await resolveExisting(fs, trim(dir))) === trim(await resolveExisting(fs, trim(home)));
}

/**
 * Why a config-set skills directory is not scanned, or undefined when it is:
 * the home itself (`home`), outside the user's home or in a credential store (`outside` — the probe
 * reports such trees `refused`), or over the remote probe's entry limit.
 */
export async function skillRootGap(fs: FSProvider, dir: string, home: string): Promise<UnscannedSkillsDir['reason'] | undefined> {
  if (!isAbsolute(dir)) return 'relative';
  const refused = async (): Promise<UnscannedSkillsDir['reason']> => ((await isHomeItself(fs, dir, home)) ? 'home' : 'outside');
  if (manifestCoversTree(fs, dir)) {
    // An agent's own tree: walked, unless it lies in the home as written and
    // a link takes it out of the home or into a credential store
    if (fs.kind === 'snapshot') {
      const gap = configTreeGap(fs, dir);
      return gap === 'refused' ? refused() : gap;
    }
    const p = normalize(dir);
    const h = normalize(home).replace(/(.)\/$/, '$1');
    if (!isAbsolute(home) || !strictlyWithin(p, h) || classifySensitivePath(p).length > 0) return undefined;
    return (await inHomeOutsideStores(fs, dir, home)) ? undefined : refused();
  }
  if (fs.kind === 'snapshot') {
    const status = configTreeStatus(fs, dir);
    if (status === 'collected') return undefined;
    if (status === 'limit') return 'limit';
    if (status === 'refused') return refused();
  }
  if (await isHomeItself(fs, dir, home)) return 'home';
  if (!(await inHomeOutsideStores(fs, dir, home))) return 'outside';
  const gap = configTreeGap(fs, dir);
  return gap === 'refused' ? 'outside' : gap;
}

/**
 * The scanned home `dir` lies in — the longest one, as written, else once
 * resolved — or undefined (probe/config_roots.go homeOf).
 */
export async function homeOfDir(fs: FSProvider, dir: string, homes: readonly string[]): Promise<string | undefined> {
  if (!isAbsolute(dir)) return undefined;
  const p = normalize(dir);
  const trim = (x: string): string => normalize(x).replace(/(.)\/$/, '$1');
  const written = homes.filter(h => isAbsolute(h) && strictlyWithin(p, trim(h))).sort((a, b) => b.length - a.length);
  if (written.length > 0) return written[0];
  const real = await resolveExisting(fs, p);
  let best: string | undefined;
  for (const h of homes) {
    if (!isAbsolute(h) || !strictlyWithin(real, await resolveExisting(fs, trim(h)))) continue;
    if (!best || h.length > best.length) best = h;
  }
  return best;
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
  for (const root of roots) {
    const reason = await skillRootGap(fs, root, home);
    if (reason) unscanned.push({ path: root, reason });
    else scan.push(root);
  }
  return { scan, unscanned };
}

/** The sentence reports and the inventory give for an unscanned skills directory. */
export function unscannedReason(reason: UnscannedSkillsDir['reason']): string {
  switch (reason) {
    case 'home':
      return 'not scanned: skills directory set to the home directory itself — VASO doesn\'t walk the whole home (locally or remotely); point it at a dedicated folder';
    case 'outside':
      return 'not scanned: skills directory set outside the user\'s home or inside a credential store — VASO doesn\'t walk it (locally or remotely); review it by hand';
    case 'limit':
      return 'not scanned: skills directory holds more entries than the remote probe collects (10000) — not verified; scan the host locally to check these skills';
    case 'relative':
      return 'not scanned: skills directory set as a relative path, which the agent resolves against its working directory — not verified; set an absolute path';
  }
}
