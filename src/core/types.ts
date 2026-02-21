export type Severity = 'critical' | 'warning' | 'info';
export type Grade = 'A' | 'B' | 'C' | 'D' | 'F';
export type AgentType = 'openclaw' | 'nanoclaw' | 'picoclaw' | 'mcp' | 'ironclaw' | 'nanobot' | 'zeroclaw';
export type CheckCategory = 'config' | 'skills' | 'ioc' | 'network' | 'runtime' | 'policy' | 'mcp' | 'ironclaw' | 'nanobot' | 'zeroclaw';
export type OutputFormat = 'terminal' | 'json' | 'sarif' | 'markdown' | 'html';

export interface Evidence {
  file: string;
  line?: number;
  snippet?: string;
  detail?: string;
}

export interface CheckResult {
  id: string;
  name: string;
  category: CheckCategory;
  severity: Severity;
  passed: boolean;
  message: string;
  evidence?: Evidence[];
  fixable?: boolean;
  fixDescription?: string;
}

export interface CheckModule {
  id: string;
  name: string;
  category: CheckCategory;
  severity: Severity;
  description: string;
  supportedAgents?: AgentType[];
  supportedPlatforms?: NodeJS.Platform[];
  run(context: ScanContext): Promise<CheckResult>;
  fix?(context: ScanContext): Promise<FixResult>;
}

export interface ParsedConfig {
  raw: string;
  format: 'json' | 'yaml' | 'env' | 'toml' | 'unknown';
  filePath: string;
  data: Record<string, unknown>;
}

export interface GatewayInfo {
  host?: string;
  port?: number;
  authMode?: string;
  tls?: boolean;
}

export interface AgentInstallation {
  agent: AgentType;
  agentName?: string;
  version?: string;
  installDir: string;
  configFiles: ParsedConfig[];
  skillsDir?: string;
  skillsDirs?: string[];
  gateway?: GatewayInfo;
  profile?: string;
  user?: string;
  appBundle?: string;
  cliBinary?: string;
}

export interface ScanContext {
  installation: AgentInstallation;
  configs: ParsedConfig[];
  platform: NodeJS.Platform;
  skillFiles?: string[];
  mcpConfigs?: import('../mcp/types.js').MCPConfig[];
  mcpServerSources?: import('../mcp/types.js').MCPServerSource[];
}

export interface AgentScanResult {
  agent: AgentType;
  installation: AgentInstallation;
  results: CheckResult[];
  score: number;
  grade: Grade;
}

export interface ScanResult {
  timestamp: string;
  agents: AgentScanResult[];
  totalScore: number;
  totalGrade: Grade;
  summary: {
    critical: number;
    warning: number;
    info: number;
    passed: number;
    total: number;
  };
}

export interface ScanOptions {
  agentFilter?: string;
  format?: OutputFormat;
  saveBaseline?: boolean;
  diff?: boolean;
  allUsers?: boolean;
}

export interface FixResult {
  checkId: string;
  applied: boolean;
  message: string;
  backupPath?: string;
}
