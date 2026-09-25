import type { AgentInstallation, ParsedConfig } from '../core/types.js';

/**
 * Drop project-level config files that a user-level installation already
 * loaded. Running from $HOME makes `<cwd>/.claude` (etc.) the user dir
 * itself; without this the same files scan twice and every finding doubles.
 */
export function withoutLoadedConfigs(
  projectConfigs: ParsedConfig[],
  installations: AgentInstallation[],
): ParsedConfig[] {
  const loaded = new Set(installations.flatMap(i => i.configFiles.map(c => c.filePath)));
  return projectConfigs.filter(c => !loaded.has(c.filePath));
}
