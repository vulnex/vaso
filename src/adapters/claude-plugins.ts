import { isAbsolute, join, normalize, relative, sep } from 'node:path';
import type { FSProvider } from '../core/fs-provider.js';
import type { ParsedConfig, UnscannedSkillsDir } from '../core/types.js';
import { cleanSkillRoot, screenSkillRoots } from '../core/skill-root-scope.js';
import { parseJsonLenient } from '../core/jsonc.js';

/**
 * Claude Code plugins (code.claude.com/docs/en/plugins): `/plugin install`
 * copies a plugin into `<claudeDir>/plugins/cache/<marketplace>/<plugin>/<version>/`
 * and records it in `plugins/installed_plugins.json` (v2:
 * `{ plugins: { "<plugin>@<marketplace>": [{ scope, projectPath?, installPath, version, … }] } }`).
 * Its skills (`skills/<name>/SKILL.md`, and the directories its
 * `.claude-plugin/plugin.json` lists under `skills`) load as `<plugin>:<name>`
 * while `enabledPlugins["<plugin>@<marketplace>"]` in the settings isn't false.
 */

export interface ClaudePlugin {
  /** `<plugin>@<marketplace>` */
  id: string;
  name: string;
  installPath: string;
  enabled: boolean;
  /** Install scope: `user`, `managed`, or `project` / `local` (one repo, `projectPath`). */
  scope: string;
}

/**
 * Install scopes: user and managed apply to every session of the user,
 * project and local to sessions in one repo (`projectPath`) — installed on
 * this machine all the same, under the same cache.
 */
const SCOPES = new Set(['user', 'managed', 'project', 'local']);

/**
 * The plugins `installed_plugins.json` records, with whether the settings
 * leave them enabled (the last settings file that names one wins: user,
 * local, then managed — the order `configs` holds them in). A project- or
 * local-scope plugin is judged by those settings too: its repo's own
 * settings are read by neither scan (a remote probe doesn't know the repo). Only
 * install paths of the cache's own shape (`plugins/cache/<marketplace>/<plugin>/<version>`)
 * are taken: that is where Claude Code installs them, and what the remote
 * probe collects as skill trees (the adapter's plugin skills glob).
 */
export async function claudePlugins(claudeDir: string, configs: readonly ParsedConfig[], fs: FSProvider): Promise<ClaudePlugin[]> {
  let data: unknown;
  try {
    data = JSON.parse(await fs.readFile(join(claudeDir, 'plugins', 'installed_plugins.json')));
  } catch {
    return [];
  }
  const plugins = (data as { plugins?: unknown } | null)?.plugins;
  if (!plugins || typeof plugins !== 'object' || Array.isArray(plugins)) return [];
  const cache = join(claudeDir, 'plugins', 'cache');
  const out: ClaudePlugin[] = [];
  for (const [id, raw] of Object.entries(plugins as Record<string, unknown>)) {
    const entries = Array.isArray(raw) ? raw : [raw];
    for (const entry of entries) {
      if (!entry || typeof entry !== 'object') continue;
      const { scope, installPath } = entry as { scope?: unknown; installPath?: unknown };
      if (scope !== undefined && !(typeof scope === 'string' && SCOPES.has(scope))) continue;
      if (typeof installPath !== 'string') continue;
      const path = normalize(installPath);
      const rel = relative(cache, path).split(sep);
      if (rel.length !== 3 || rel.some(s => !s || s === '..' || s === '.')) continue;
      if (out.some(p => p.installPath === path)) continue;
      out.push({ id, name: id.split('@')[0] || rel[1], installPath: path, enabled: pluginEnabled(id, configs), scope: typeof scope === 'string' ? scope : 'user' });
    }
  }
  return out;
}

function pluginEnabled(id: string, configs: readonly ParsedConfig[]): boolean {
  let enabled = true;
  for (const c of configs) {
    const map = (c.data as Record<string, unknown> | undefined)?.enabledPlugins;
    if (!map || typeof map !== 'object' || Array.isArray(map)) continue;
    const value = (map as Record<string, unknown>)[id];
    if (typeof value === 'boolean') enabled = value;
  }
  return enabled;
}

/** The skills directory of a plugin. */
export function claudePluginSkillsDir(plugin: ClaudePlugin): string {
  return join(plugin.installPath, 'skills');
}

/** At most this many skills paths are read from one plugin.json. */
const MAX_PLUGIN_SKILL_PATHS = 64;

/**
 * The skills directories a plugin's `.claude-plugin/plugin.json` lists
 * under `skills` (a path or an array of paths, relative to the plugin root;
 * loaded in addition to `skills/`), resolved as the remote probe resolves
 * them (configRoots `configParent`: `~/` is the home, an absolute path is
 * itself) and screened like any config-set skills directory: one that
 * leaves the plugin for the home itself, an OS directory, another user's
 * home or a credential store is not scanned (skill-root-scope.ts).
 */
export async function claudePluginExtraSkillsDirs(
  plugin: ClaudePlugin,
  home: string,
  fs: FSProvider,
): Promise<{ scan: string[]; unscanned: UnscannedSkillsDir[] }> {
  let data: unknown;
  try {
    data = parseJsonLenient(await fs.readFile(join(plugin.installPath, '.claude-plugin', 'plugin.json')));
  } catch {
    return { scan: [], unscanned: [] };
  }
  const raw = (data as { skills?: unknown } | null)?.skills;
  const values = (Array.isArray(raw) ? raw : [raw])
    .filter((v): v is string => typeof v === 'string' && v.trim() !== '' && !v.includes('\0'))
    .slice(0, MAX_PLUGIN_SKILL_PATHS)
    .map(v => v.trim());
  const dirs = values.map(v => cleanSkillRoot(
    v === '~' ? home : v.startsWith('~/') ? join(home, v.slice(2)) : isAbsolute(v) ? v : join(plugin.installPath, v)));
  const own = cleanSkillRoot(claudePluginSkillsDir(plugin));
  return screenSkillRoots(fs, [...new Set(dirs)].filter(d => d !== own), home);
}

/**
 * The plugin a skills directory belongs to: one inside a plugin's install
 * path (`…/plugins/cache/<marketplace>/<plugin>/<version>/skills`, or a
 * directory its plugin.json adds), else undefined.
 */
export function pluginOfSkillsDir(dir: string): string | undefined {
  const parts = normalize(dir).split(sep);
  for (let i = parts.length - 4; i >= 1; i--) {
    if (parts[i] === 'cache' && parts[i - 1] === 'plugins') return parts[i + 2] || undefined;
  }
  return undefined;
}
