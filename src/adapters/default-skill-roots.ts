import { isAbsolute } from 'node:path';
import type { FSProvider } from '../core/fs-provider.js';
import type { AgentInstallation, UnscannedSkillsDir } from '../core/types.js';
import { expandManifestGlob, expandedGlobRegex, manifestCoversTree, manifestSkillGlobs, pathChain, splitGlob } from '../core/probe-coverage.js';
import { envTreeRefusal, homeOfDir, refusalPhrase, skillRootGap, unscannedDir } from '../core/skill-root-scope.js';
import { getAllSkillsDirs } from '../core/utils.js';
import { getUserHomeDirs } from './openclaw.js';

/**
 * An agent's own skills directories (the trees the probe's manifest walks:
 * `~/.claude/skills`, `~/.picoclaw/workspace-<id>/skills`) that lie in a home
 * and are links — or lie under one, `~/.claude` → another volume — are walked
 * wherever they lead, except where no skills tree is walked (an OS
 * directory, another user's home, the home itself, a credential store —
 * skill-root-scope.ts): those are not scanned — moved to unscannedSkillsDirs,
 * which SKL-002 reports — on local and remote scans alike (skillRootGap; the
 * probe's linkedOutSkillBase and collectLinkedSkillBases). Config-set
 * directories are screened by their adapters already; anything else is left
 * as the adapter gave it.
 *
 * A directory only manifest globs an environment variable roots walk
 * (`${OPENCLAW_STATE_DIR}/skills/**`), where the probe refuses each of them
 * (envGlobRefused: its base is the root, a home or above, another user's
 * home, a credential store), is not scanned either — wherever it lies.
 */
export async function screenDefaultSkillRoots(
  installations: AgentInstallation[],
  fs: FSProvider,
  allUsers?: boolean,
): Promise<AgentInstallation[]> {
  if (!installations.some(i => getAllSkillsDirs(i).length > 0)) return installations;
  let homes: string[] | undefined;
  const out: AgentInstallation[] = [];
  for (const inst of installations) {
    const roots = getAllSkillsDirs(inst);
    const keep: string[] = [];
    const moved: UnscannedSkillsDir[] = [];
    for (const root of roots) {
      if (!isAbsolute(root) || !manifestCoversTree(fs, root)) {
        keep.push(root);
        continue;
      }
      homes ??= [...new Set([...(await getUserHomeDirs(allUsers, fs)).map(h => h.home), fs.homedir()])];
      const envRefused = await envOnlyRefusal(fs, root, homes);
      if (envRefused) {
        moved.push(envRefused);
        continue;
      }
      const home = await homeOfDir(fs, root, homes);
      const reason = home ? await skillRootGap(fs, root, home) : undefined;
      if (reason && home) moved.push(await unscannedDir(fs, root, reason, home, true));
      else keep.push(root);
    }
    if (moved.length === 0) {
      out.push(inst);
      continue;
    }
    const known = new Set((inst.unscannedSkillsDirs ?? []).map(u => u.path));
    out.push({
      ...inst,
      skillsDir: inst.skillsDir !== undefined && keep.includes(inst.skillsDir) ? inst.skillsDir : keep[0],
      skillsDirs: keep,
      unscannedSkillsDirs: [...(inst.unscannedSkillsDirs ?? []), ...moved.filter(u => !known.has(u.path))],
    });
  }
  return out;
}

/**
 * `root` lies only in manifest skills trees an environment variable roots,
 * and the probe refuses every one of them (envTreeRefusal): not scanned,
 * with the kind of place the glob's base is. Undefined when a manifest tree
 * that holds it is walked.
 */
async function envOnlyRefusal(fs: FSProvider, root: string, homes: readonly string[]): Promise<UnscannedSkillsDir | undefined> {
  const chain = pathChain(root);
  let refusal: string | undefined;
  for (const glob of manifestSkillGlobs()) {
    const env = glob.startsWith('${');
    for (const home of env ? [fs.homedir()] : homes) {
      const exp = expandManifestGlob(fs, glob, home);
      if (!exp) continue;
      // A variable set to `/` leaves the prefix `/` before a tail `/…`
      const prefix = exp.prefix === '/' && exp.tail.startsWith('/') ? '' : exp.prefix;
      const re = expandedGlobRegex(prefix, exp.tail.replace(/\/\*\*$/, ''));
      if (!re || !chain.some(d => re.test(d))) continue;
      if (!env) return undefined;
      const label = await envTreeRefusal(fs, splitGlob(prefix + exp.tail).base, homes);
      if (!label) return undefined;
      refusal ??= label;
    }
  }
  return refusal === undefined ? undefined : { path: root, reason: 'outside', refusedAs: refusalPhrase(refusal), agentDefault: true };
}
