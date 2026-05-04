export type Severity = 'critical' | 'warning' | 'info';
export type Grade = 'A' | 'B' | 'C' | 'D' | 'F';
export type AgentType = 'openclaw' | 'nanoclaw' | 'picoclaw' | 'mcp' | 'ironclaw' | 'nanobot' | 'zeroclaw' | 'nemoclaw' | 'hermes' | 'lyrie' | 'claude-code' | 'codex' | 'opencode' | 'gemini-cli' | 'qwen-code' | 'copilot-cli' | 'cursor-cli' | 'skill-audit';
export type CheckCategory = 'config' | 'skills' | 'ioc' | 'network' | 'runtime' | 'policy' | 'mcp' | 'openclaw' | 'nanoclaw' | 'ironclaw' | 'nanobot' | 'zeroclaw' | 'lyrie' | 'hermes' | 'advisory' | 'coding-agent';

/**
 * Coding agents (interactive developer tools) — different threat model from
 * autonomous server frameworks. Used by checks via `excludedAgents` to skip
 * server-only concepts like gateway binding, rate limiting, LaunchAgents, etc.
 */
export const CODING_AGENTS: AgentType[] = ['claude-code', 'codex', 'opencode', 'gemini-cli', 'qwen-code', 'copilot-cli', 'cursor-cli'];
export type OutputFormat = 'terminal' | 'json' | 'sarif' | 'markdown' | 'html' | 'csv' | 'junit';

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
  excludedAgents?: AgentType[];
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

/**
 * One model the agent is configured to use. Shape is intentionally flat so
 * that future audit/policy work (deprecation flags, license, CVE matching)
 * can layer on without churning callers.
 */
export interface ModelRef {
  /** Model identifier as it appears in the config (e.g. "claude-opus-4-5", "nvidia/nemotron-3-super-120b-a12b"). */
  id: string;
  /** Provider/router when separable from the id (e.g. "ollama", "anthropic", "nvidia-nim"). */
  provider?: string;
  /** Disambiguator when an agent declares the same model under multiple slots — e.g. nemoclaw sandbox name, openclaw profile. */
  via?: string;
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
  models?: ModelRef[];
  profile?: string;
  user?: string;
  appBundle?: string;
  cliBinary?: string;
}

export interface ScanContext {
  installation: AgentInstallation;
  configs: ParsedConfig[];
  platform: NodeJS.Platform;
  fs: import('./fs-provider.js').FSProvider;
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
  host?: string;
  label?: string;
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

/**
 * Privilege gradient model — used to emit USecVisLib privilege-gradient configs
 * (PRD-006). Each adapter optionally declares its own ZoneGraph; adapters that
 * don't implement getZoneGraph() get the generic 4-zone fallback.
 */

export interface Zone {
  id: string;
  label: string;
  trustLevel: number;
}

export interface ZoneComponent {
  id: string;
  label: string;
  zone: string;
  guardCheckIds?: string[];
}

export interface ZoneEdge {
  from: string;
  to: string;
  label?: string;
  kind?: 'data' | 'control' | 'resource' | 'feedback';
  triggerCheckIds?: string[];
}

export interface ZoneGraph {
  zones: Zone[];
  components: ZoneComponent[];
  edges: ZoneEdge[];
}
