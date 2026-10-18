import type { FSProvider } from '../core/fs-provider.js';
import type { AgentInstallation, ParsedConfig } from '../core/types.js';

/**
 * Working directory whose project configs a scan reads, or undefined when
 * there is none: a remote or snapshot scan reads another host, where this
 * process's cwd means nothing (the probe collects no project files). Using it
 * anyway made results depend on where vaso ran — a scan of a host from its
 * own home found a "project" that the same scan from elsewhere did not.
 */
export function scanCwd(fs: FSProvider): string | undefined {
  return fs.kind === 'snapshot' ? undefined : process.cwd();
}

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

/**
 * Whether `dir` is the install dir of an installation already detected,
 * compared resolved like withoutLoadedConfigs: from a symlinked $HOME the
 * working directory's `.claude` (etc.) is the user dir under another name.
 */
export async function isLoadedInstallDir(dir: string, installations: AgentInstallation[], fs: FSProvider): Promise<boolean> {
  const real = (p: string) => fs.realpath(p).catch(() => p);
  const target = await real(dir);
  return (await Promise.all(installations.map(i => real(i.installDir)))).includes(target);
}
