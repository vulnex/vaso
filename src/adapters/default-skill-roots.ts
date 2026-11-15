import { isAbsolute } from 'node:path';
import type { FSProvider } from '../core/fs-provider.js';
import type { AgentInstallation, UnscannedSkillsDir } from '../core/types.js';
import { manifestCoversTree } from '../core/probe-coverage.js';
import { homeOfDir, skillRootGap } from '../core/skill-root-scope.js';
import { getAllSkillsDirs } from '../core/utils.js';
import { getUserHomeDirs } from './openclaw.js';

/**
 * An agent's own skills directories (the trees the probe's manifest walks:
 * `~/.claude/skills`, `~/.picoclaw/workspace-<id>/skills`) that lie in a home
 * but are links out of it or into a credential store are not scanned — moved
 * to unscannedSkillsDirs, which SKL-002 reports — on local and remote scans
 * alike (skillRootGap; the probe's refuseLinkedSkillBase and
 * collectLinkedSkillBases). Config-set directories are screened by their
 * adapters already; anything else is left as the adapter gave it.
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
      const home = await homeOfDir(fs, root, homes);
      const reason = home ? await skillRootGap(fs, root, home) : undefined;
      if (reason) moved.push({ path: root, reason });
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
