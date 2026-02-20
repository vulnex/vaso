import type { AgentType, AgentInstallation, GatewayInfo } from '../core/types.js';

export interface AgentAdapter {
  readonly agent: AgentType;
  readonly displayName: string;

  detect(): Promise<AgentInstallation | null>;
  getConfigPaths(): string[];
  getSkillsDir(installDir: string): string | undefined;
  getGatewayInfo(config: Record<string, unknown>): GatewayInfo | undefined;
  getMemoryFiles?(installDir: string): string[];
  getCredentialPaths?(installDir: string): string[];
  getCLICommand?(): string;
}
