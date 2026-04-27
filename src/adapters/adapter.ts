import type { AgentType, AgentInstallation, GatewayInfo, ZoneGraph } from '../core/types.js';

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
  getMemoryFiles?(installDir: string): string[];
  getCredentialPaths?(installDir: string): string[];
  getCLICommand?(): string;
  getProbeManifest?(): import('../core/snapshot-types.js').ProbeManifest;
  getZoneGraph?(): ZoneGraph;
}
