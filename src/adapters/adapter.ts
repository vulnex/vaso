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
   *  is passed for adapters that need to read env vars (e.g. ANTHROPIC_MODEL). */
  getModels?(configs: ParsedConfig[], fs?: import('../core/fs-provider.js').FSProvider): ModelRef[];
  getMemoryFiles?(installDir: string): string[];
  getCredentialPaths?(installDir: string): string[];
  getCLICommand?(): string;
  getProbeManifest?(): import('../core/snapshot-types.js').ProbeManifest;
  getZoneGraph?(): ZoneGraph;
}
