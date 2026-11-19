import { join, normalize, relative, sep } from 'node:path';
import type { FSProvider } from '../core/fs-provider.js';
import type { ParsedConfig } from '../core/types.js';

/**
 * Claude Code plugins (code.claude.com/docs/en/plugins): `/plugin install`
 * copies a plugin into `<claudeDir>/plugins/cache/<marketplace>/<plugin>/<version>/`
 * and records it in `plugins/installed_plugins.json` (v2:
 * `{ plugins: { "<plugin>@<marketplace>": [{ scope, installPath, version, … }] } }`).
 * Its skills (`skills/<name>/SKILL.md`) load as `<plugin>:<name>` while
 * `enabledPlugins["<plugin>@<marketplace>"]` in the settings isn't false.
 */

export interface ClaudePlugin {
  /** `<plugin>@<marketplace>` */
  id: string;
  name: string;
  installPath: string;
  enabled: boolean;
}

/** Install scopes that apply to every session of the user (project/local ones apply to one repo). */
const USER_SCOPES = new Set(['user', 'managed']);

/**
 * The user-scope plugins `installed_plugins.json` records, with whether the
 * settings leave them enabled (the last settings file that names one wins:
 * user, local, then managed — the order `configs` holds them in). Only
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
      if (scope !== undefined && !(typeof scope === 'string' && USER_SCOPES.has(scope))) continue;
      if (typeof installPath !== 'string') continue;
      const path = normalize(installPath);
      const rel = relative(cache, path).split(sep);
      if (rel.length !== 3 || rel.some(s => !s || s === '..' || s === '.')) continue;
      if (out.some(p => p.installPath === path)) continue;
      out.push({ id, name: id.split('@')[0] || rel[1], installPath: path, enabled: pluginEnabled(id, configs) });
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

/** The plugin a skills directory belongs to (`…/plugins/cache/<marketplace>/<plugin>/<version>/skills`), else undefined. */
export function pluginOfSkillsDir(dir: string): string | undefined {
  const parts = normalize(dir).split(sep);
  const n = parts.length;
  if (n < 6 || parts[n - 1] !== 'skills' || parts[n - 5] !== 'cache' || parts[n - 6] !== 'plugins') return undefined;
  return parts[n - 3];
}
