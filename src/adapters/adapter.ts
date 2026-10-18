import type { FSProvider } from '../core/fs-provider.js';
import type { AgentType, AgentInstallation, GatewayInfo, ModelRef, ParsedConfig, ZoneGraph } from '../core/types.js';

export interface DetectOptions {
  allUsers?: boolean;
  fs?: import('../core/fs-provider.js').FSProvider;
}

export interface AgentAdapter {
  readonly agent: AgentType;
  readonly displayName: string;

  detect(options?: DetectOptions): Promise<AgentInstallation[]>;
  getConfigPaths(): string[];
  getSkillsDir(installDir: string): string | undefined;
  getGatewayInfo(config: Record<string, unknown>): GatewayInfo | undefined;
  /** Extract the LLM models the agent is configured to use. Optional — adapters
   *  whose configs don't expose a model field can omit this. The `fs` argument
   *  is passed for adapters that need to read env vars (e.g. ANTHROPIC_MODEL)
   *  or walk auxiliary files (e.g. codex's session jsonls). May be sync or
   *  async; callers should `await`. */
  getModels?(configs: ParsedConfig[], fs?: import('../core/fs-provider.js').FSProvider): ModelRef[] | Promise<ModelRef[]>;
  getMemoryFiles?(installDir: string): string[];
  /** `fs` is the provider being scanned (a remote snapshot on --host); adapters
   *  resolving paths from $HOME must use it, not the scanner host's home. */
  getCredentialPaths?(installDir: string, fs?: FSProvider): string[];
  getCLICommand?(): string;
  getProbeManifest?(): import('../core/snapshot-types.js').ProbeManifest;
  getZoneGraph?(): ZoneGraph;
}

/**
 * Credential stores an installation declares. A project installation has
 * none: its installDir is a repository (or the repo's .cursor/ etc.), where
 * the adapter's file names — config.json, settings.json, hooks.json — are
 * ordinary project files that POL-003/CFG-003 would flag and `vaso fix`
 * would chmod. Every adapter keeps its credentials at user level.
 */
export function credentialPathsFor(
  adapter: AgentAdapter | undefined,
  installation: AgentInstallation,
  fs: FSProvider,
): string[] | undefined {
  if (installation.profile === 'project') return undefined;
  return adapter?.getCredentialPaths?.(installation.installDir, fs);
}
