import type { FSProvider } from '../core/fs-provider.js';
import type { AgentInstallation, ParsedConfig } from '../core/types.js';

/**
 * Drop project-level config files that a user-level installation already
 * loaded. Running from $HOME makes `<cwd>/.claude` (etc.) the user dir
 * itself; without this the same files scan twice and every finding doubles.
 * Paths are compared resolved: the working directory is always a real path,
 * while $HOME may be spelled through a symlink (macOS `/var` → `/private/var`,
 * a home on a linked volume), and the same file then looked like two.
 */
export async function withoutLoadedConfigs(
  projectConfigs: ParsedConfig[],
  installations: AgentInstallation[],
  fs: FSProvider,
): Promise<ParsedConfig[]> {
  const real = (p: string) => fs.realpath(p).catch(() => p);
  const loaded = new Set(await Promise.all(installations.flatMap(i => i.configFiles.map(c => real(c.filePath)))));
  const keep = await Promise.all(projectConfigs.map(async c => !loaded.has(await real(c.filePath))));
  return projectConfigs.filter((_, i) => keep[i]);
}
