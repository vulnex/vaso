import { basename, dirname, isAbsolute, join, normalize, relative } from 'node:path';
import type { FSProvider } from './fs-provider.js';
import type { UnscannedSkillsDir } from './types.js';
import { classifySensitivePath } from '../analyzers/sensitive-paths.js';
import { configTreeGap, manifestCoversTree } from './probe-coverage.js';
import { relEscapes } from './path-rel.js';

/**
 * Skills directories an agent's config sets (an OpenClaw extraDir, a Nanobot
 * or ZeroClaw workspace) are walked only strictly inside the home of the user
 * whose config names them, and never in a credential store (SENSITIVE_SINKS)
 * — as written and once resolved. The remote probe applies the same rule
 * (treeAllowed in probe/config_roots.go), so a config pointing a skill root
 * at `/`, `/etc`, another user's home, the home itself or `~/.ssh` is reported
 * "not scanned" by local and remote scans alike, instead of one walking the
 * whole disk and the other passing it silently. Directories the probe's
 * manifest walks anyway (an agent's own default trees) are always scanned.
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
  if (h === '/' || !strictlyWithin(p, h) || classifySensitivePath(p).length > 0) return false;
  const real = await resolveExisting(fs, p);
  const realHome = await resolveExisting(fs, h);
  return strictlyWithin(real, realHome) && classifySensitivePath(real).length === 0;
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
  if (manifestCoversTree(fs, dir)) return undefined;
  if (await isHomeItself(fs, dir, home)) return 'home';
  if (!(await inHomeOutsideStores(fs, dir, home))) return 'outside';
  const gap = configTreeGap(fs, dir);
  return gap === 'refused' ? 'outside' : gap;
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
