import { isAbsolute, join } from 'node:path';
import type { FSProvider } from '../core/fs-provider.js';
import type { UnscannedSkillsDir } from '../core/types.js';
import { dirExistsOrUncollected } from '../core/probe-coverage.js';
import { cleanSkillRoot, screenSkillRoots } from '../core/skill-root-scope.js';
import { loadConfigIfPresent } from './load-if-present.js';

/**
 * Every skills directory a Hermes data root loads from, as Hermes resolves
 * them (agent/skill_utils.py `get_all_skills_dirs`, hermes_cli/profiles.py):
 *
 * - `<home>/skills`, the root's own directory;
 * - `skills.external_dirs` in its config.yaml (a string or a list; `${VAR}`
 *   and `~` expanded, relative entries against the data root);
 * - each profile `<home>/profiles/<name>/` — a data root of its own, run with
 *   `hermes -p <name>` — with its `skills/` and its own external_dirs.
 *
 * Directories a config sets are walked only where a skills tree may be
 * (skill-root-scope), like every adapter's config-set roots; the rest are
 * reported as not scanned.
 */
export async function hermesSkillRoots(
  hermesHome: string,
  mainConfig: Record<string, unknown> | undefined,
  fs: FSProvider,
  home: string,
): Promise<{ roots: string[]; unscanned: UnscannedSkillsDir[] }> {
  const own = join(hermesHome, 'skills');
  const defaults: string[] = [];
  const configSet: string[] = [...externalSkillDirs(mainConfig, hermesHome, fs, home)];
  for (const name of await listDirs(join(hermesHome, 'profiles'), fs)) {
    const profileDir = join(hermesHome, 'profiles', name);
    defaults.push(join(profileDir, 'skills'));
    let profileConfig: Record<string, unknown> | undefined;
    try {
      profileConfig = (await loadConfigIfPresent(join(profileDir, 'config.yaml'), fs))?.data;
    } catch {
      profileConfig = undefined;
    }
    configSet.push(...externalSkillDirs(profileConfig, profileDir, fs, home));
  }
  const roots = [own];
  for (const d of defaults) if (!roots.includes(d) && await dirExistsOrUncollected(fs, d)) roots.push(d);
  const { scan, unscanned } = await screenSkillRoots(fs, [...new Set(configSet)].filter(d => !roots.includes(d)), home);
  for (const d of scan) if (!roots.includes(d) && await dirExistsOrUncollected(fs, d)) roots.push(d);
  return { roots, unscanned };
}

/**
 * `skills.external_dirs` of one data root's config.yaml, as absolute paths.
 * An entry naming an unset `${VAR}` is skipped: Hermes would keep the
 * reference literally and find no such directory.
 */
export function externalSkillDirs(
  config: Record<string, unknown> | undefined,
  dataRoot: string,
  fs: FSProvider,
  home: string,
): string[] {
  const skills = config?.skills;
  if (!skills || typeof skills !== 'object' || Array.isArray(skills)) return [];
  let raw = (skills as Record<string, unknown>).external_dirs;
  if (typeof raw === 'string') raw = [raw];
  if (!Array.isArray(raw)) return [];
  const out: string[] = [];
  for (const entry of raw) {
    if (typeof entry !== 'string') continue;
    let v = entry.trim();
    if (!v) continue;
    let unresolved = false;
    v = v.replace(/\$\{([A-Za-z_][A-Za-z0-9_]*)\}/g, (_m, name: string) => {
      const value = fs.getEnv(name);
      if (value === undefined) unresolved = true;
      return value ?? '';
    });
    if (unresolved || !v.trim()) continue;
    if (v === '~') v = home;
    else if (v.startsWith('~/')) v = join(home, v.slice(2));
    else if (!isAbsolute(v)) v = join(dataRoot, v);
    out.push(cleanSkillRoot(v));
  }
  return out;
}

async function listDirs(dir: string, fs: FSProvider): Promise<string[]> {
  try {
    return (await fs.readdirEntries(dir)).filter(e => e.isDirectory).map(e => e.name).sort();
  } catch {
    return [];
  }
}
