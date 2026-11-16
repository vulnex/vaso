export type Severity = 'critical' | 'warning' | 'info';
export type Grade = 'A' | 'B' | 'C' | 'D' | 'F';
export type AgentType = 'openclaw' | 'nanoclaw' | 'picoclaw' | 'mcp' | 'ironclaw' | 'nanobot' | 'zeroclaw' | 'nemoclaw' | 'openshell' | 'hermes' | 'lyrie' | 'atomic-agent' | 'claude-code' | 'claude-desktop' | 'chatgpt-desktop' | 'codex' | 'opencode' | 'gemini-cli' | 'qwen-code' | 'copilot-cli' | 'cursor-cli' | 'windsurf' | 'devin' | 'meta-muse' | 'comet' | 'abacus' | 'grok-bot' | 'skill-audit';
export type CheckCategory = 'config' | 'skills' | 'ioc' | 'network' | 'runtime' | 'policy' | 'mcp' | 'openclaw' | 'nanoclaw' | 'picoclaw' | 'ironclaw' | 'nanobot' | 'zeroclaw' | 'lyrie' | 'hermes' | 'atomic-agent' | 'openshell' | 'advisory' | 'coding-agent';

export const AGENT_TYPES: readonly AgentType[] = [
  'openclaw', 'nanoclaw', 'picoclaw', 'mcp', 'ironclaw', 'nanobot',
  'zeroclaw', 'nemoclaw', 'openshell', 'hermes', 'lyrie', 'atomic-agent', 'claude-code',
  'claude-desktop', 'chatgpt-desktop', 'codex', 'opencode',
  'gemini-cli', 'qwen-code', 'copilot-cli', 'cursor-cli',
  'windsurf', 'devin', 'meta-muse', 'comet', 'abacus', 'grok-bot', 'skill-audit',
];

export function isScannableAgentType(v: string): v is AgentType {
  return v !== 'mcp' && v !== 'skill-audit' && (AGENT_TYPES as readonly string[]).includes(v);
}

export const CHECK_CATEGORIES: readonly CheckCategory[] = [
  'config', 'skills', 'ioc', 'network', 'runtime', 'policy', 'mcp',
  'openclaw', 'nanoclaw', 'picoclaw', 'ironclaw', 'nanobot', 'zeroclaw', 'lyrie',
  'hermes', 'atomic-agent', 'openshell', 'advisory', 'coding-agent',
];

/**
 * Coding agents (interactive developer tools) — different threat model from
 * autonomous server frameworks. Used by checks via `excludedAgents` to skip
 * server-only concepts like gateway binding, rate limiting, LaunchAgents, etc.
 */
export const CODING_AGENTS: AgentType[] = ['claude-code', 'claude-desktop', 'chatgpt-desktop', 'codex', 'opencode', 'gemini-cli', 'qwen-code', 'copilot-cli', 'cursor-cli', 'windsurf', 'devin', 'meta-muse', 'comet', 'abacus', 'grok-bot'];
/**
 * Host OS, as `process.platform` reports it. Spelled out (same values as
 * Node's `Platform`) so the published typings don't need @types/node.
 */
export type Platform = 'aix' | 'android' | 'darwin' | 'freebsd' | 'haiku' | 'linux' | 'openbsd' | 'sunos' | 'win32' | 'cygwin' | 'netbsd';
export type OutputFormat = 'terminal' | 'json' | 'sarif' | 'markdown' | 'html' | 'csv' | 'junit';

export interface Evidence {
  file: string;
  line?: number;
  snippet?: string;
  detail?: string;
  /** Exposure blocked by parent-directory permissions (`markUnreachable`) or the
   *  finding sits in skill test/fixture code (`markTestCode`). When every item
   *  is mitigated, `fromEvidence` reports the result at 'info'. */
  mitigated?: boolean;
}

/** OWASP MCP Top 10 (2025) identifier, e.g. 'MCP03'. Tags MCP-related checks so
 *  reports can show OWASP MCP Top 10 coverage. */
export type OwaspMcpId =
  | 'MCP01' | 'MCP02' | 'MCP03' | 'MCP04' | 'MCP05'
  | 'MCP06' | 'MCP07' | 'MCP08' | 'MCP09' | 'MCP10';

/** OWASP Agentic AI Top 10 identifier, e.g. 'AAI003' (precize list). Tags checks
 *  so reports can show Agentic AI Top 10 coverage. The list omits deprecated
 *  (AAI004/008/010) and in-development (AAI013/015/016) entries. AAI011
 *  (Untraceability) and AAI014 (Alignment Faking) are runtime/behavioral risks a
 *  static scanner can't observe — they appear in coverage tables as gaps. */
export type OwaspAgenticId =
  | 'AAI001' | 'AAI002' | 'AAI003' | 'AAI005' | 'AAI006'
  | 'AAI007' | 'AAI009' | 'AAI011' | 'AAI012' | 'AAI014';

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
  /** Set on a generic finding (CFG-003/POL-003) whose files an agent-specific
   *  check already reports: the result passes (the finding counts once, under
   *  that check), but keeps its evidence and fix so `vaso fix` still applies
   *  it. Names the check(s) that report it. */
  foldedInto?: string;
  /** Set by the engine when the check could not be evaluated — it threw, or its
   *  adapter failed to detect/parse — rather than producing a real verdict.
   *  Distinguishes "scanned and failed the check" from "scan was incomplete".
   *  Reporters use it to report partial-scan status (e.g. SARIF
   *  invocation.executionSuccessful) instead of claiming a clean run. */
  errored?: boolean;
  /** Set by the engine on a sub-installation (e.g. an OpenClaw `agents/<name>`
   *  profile) when the parent installation already reports this exact finding.
   *  The result is passed through as `passed: true` so the finding counts once;
   *  `message` names where it is reported. */
  inherited?: boolean;
}

export interface CheckModule {
  id: string;
  name: string;
  category: CheckCategory;
  severity: Severity;
  description: string;
  supportedAgents?: AgentType[];
  excludedAgents?: AgentType[];
  supportedPlatforms?: Platform[];
  owaspMcp?: OwaspMcpId;
  owaspAgentic?: OwaspAgenticId[];
  run(context: ScanContext): Promise<CheckResult>;
  fix?(context: ScanContext): Promise<FixResult>;
}

export interface ParsedConfig {
  raw: string;
  format: 'json' | 'yaml' | 'env' | 'toml' | 'unknown';
  filePath: string;
  data: Record<string, unknown>;
  /** An administrator-managed layer the agent applies over the user's own
   *  files (Hermes `/etc/hermes`): its values win where it sets them. */
  managed?: boolean;
  /** The file began with a UTF-8 byte-order mark, stripped from `raw` (an
   *  app that reads it with a plain JSON.parse rejects the file). */
  bom?: boolean;
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
  /** Other copies of the agent's CLI on the host whose version differs from
   *  `version` — e.g. an older npm global or another nvm Node version's copy.
   *  Advisory checks evaluate each one. */
  otherInstalls?: CliInstall[];
  /** The skills this installation loads — set by `vaso detect` and `vaso scan`. */
  inventory?: AgentInventory;
  /** Skills directories no scan walks (the agent's config sets them, or a
   *  link takes its own default one, where no skills tree is walked — an OS
   *  directory, another user's home, a credential store; over the remote
   *  probe's limit; a relative path): not in skillsDirs, reported as not
   *  scanned. */
  unscannedSkillsDirs?: UnscannedSkillsDir[];
}

/** A skills directory left unscanned, and why (src/core/skill-root-scope.ts). */
export interface UnscannedSkillsDir {
  path: string;
  reason: 'home' | 'outside' | 'limit' | 'relative';
  /** Where its links lead, when it is (or lies under) a link. */
  target?: string;
  /** The kind of place it is (`home`/`outside`): "an OS directory (/etc)". */
  refusedAs?: string;
  /** An agent's own default skills directory, not one its config sets. */
  agentDefault?: true;
}

/**
 * What an installation loads: descriptive, never judged. Names and paths
 * only — a skill's description is masked and shortened, nothing else of a
 * file's content is carried.
 */
export interface AgentInventory {
  /** Every skills directory the adapter declares, and whether it exists. */
  skillsDirs: SkillsDirInfo[];
  /** Folders holding a SKILL.md (outermost one per tree). */
  skills: SkillItem[];
  /** Other folders and code files directly under a skills directory: the
   *  skill checks read them, but they hold no SKILL.md. */
  otherEntries: SkillTreeEntry[];
  /** MCP servers configured for the agent, disabled ones marked. Absent for
   *  agents whose MCP configs VASO doesn't read. */
  mcpServers?: McpServerItem[];
  /** Why the lists may be partial (a directory that can't be listed). */
  incomplete?: string[];
}

/** One MCP server as configured: names and locations only — env and header
 *  values are never carried, URLs and arguments are masked. */
export interface McpServerItem {
  name: string;
  /** The config file that declares it. */
  configFile: string;
  scope: 'user' | 'project' | 'extension';
  /** The project it applies to (project scope). */
  project?: string;
  transport: 'stdio' | 'sse' | 'streamable-http';
  command?: string;
  args?: string[];
  url?: string;
  /** The package a runner (npx, uvx, …) installs, as written, and how it is pinned. */
  package?: {
    runner: string;
    ecosystem: 'npm' | 'pypi';
    name: string;
    spec: string;
    pin: 'exact' | 'range' | 'tag' | 'none' | 'local';
  };
  envNames?: string[];
  headerNames?: string[];
  /** Switched off in its config: never launched, and not judged by the MCP checks. */
  disabled?: boolean;
  /** Ids of failed checks whose evidence names it in its config file (scan only). */
  findings?: string[];
}

/** What a host carries beyond its agents. */
export interface HostInventory {
  /** MCP servers in files no detected agent owns (VS Code, a bare project mcp.json). */
  mcpServers: McpServerItem[];
  /** The same MCP server configured for several installations, in separate config files. */
  sharedMcpServers?: SharedMcpServer[];
}

/** One MCP server several installations configure: a change to it (or a compromise of it) reaches all of them. */
export interface SharedMcpServer {
  /** What makes them the same: `npm:<name>`, `pypi:<name>`, `url:<origin><path>`, `command:<command line>`. */
  key: string;
  users: Array<{
    agent: AgentType;
    agentName?: string;
    installDir: string;
    /** The server's name in that config. */
    server: string;
    configFile: string;
    pin?: 'exact' | 'range' | 'tag' | 'none' | 'local';
  }>;
  /** At least one of them runs the package unpinned, by a range or by a moving tag. */
  unpinned: boolean;
}

export interface SkillsDirInfo {
  path: string;
  exists: boolean;
  /** Snapshot scans: the remote probe doesn't collect this directory (a config
   *  points it outside the manifest's trees), so `exists: false` means unknown. */
  unverified?: true;
}

export interface SkillItem {
  /** SKILL.md frontmatter `name`, else the folder name. */
  name: string;
  /** The skill folder, as the agent reaches it (a symlink's own path). */
  path: string;
  /** The skills directory it was found in. */
  root: string;
  scope: 'user' | 'project' | 'plugin' | 'extension' | 'managed';
  kind: 'skill-md' | 'plugin' | 'extension' | 'mcpb';
  /** SKILL.md frontmatter `description`: at most 200 characters, secrets masked. */
  description?: string;
  /** Files in it the skill checks read (SKILL.md, scripts, binaries). */
  files: number;
  /** Holds a script or binary besides SKILL.md. */
  hasCode: boolean;
  /** Where the folder really is, when it is a symlink. */
  symlinkTarget?: string;
  /** Ids of failed checks with evidence in it (scan only). */
  findings?: string[];
}

export interface SkillTreeEntry {
  path: string;
  root: string;
  type: 'directory' | 'file';
  files: number;
  hasCode: boolean;
  /** Ids of failed checks with evidence in it (scan only). */
  findings?: string[];
}

/** One copy of an agent CLI: its path and (when determinable) version. */
export interface CliInstall {
  path: string;
  version?: string;
}

export interface ScanContext {
  installation: AgentInstallation;
  configs: ParsedConfig[];
  platform: Platform;
  fs: import('./fs-provider.js').FSProvider;
  skillFiles?: string[];
  /** Files the adapter has declared as security-sensitive (credentials, auth
   *  state, etc.). Used by permission checks to avoid flagging benign config
   *  files. Pre-computed by the engine from `adapter.getCredentialPaths()` —
   *  never for a project installation (credential stores are user-level). */
  credentialPaths?: string[];
  mcpConfigs?: import('../mcp/types.js').MCPConfig[];
  mcpServerSources?: import('../mcp/types.js').MCPServerSource[];
  mcpToolBaselineStore?: import('../mcp/tool-baseline.js').ToolBaselineStore;
  /** Cross-scan state for MCP-027 (version history) and MCP-028 (config drift).
   *  Defaults to a file-backed store inside each check; injectable for tests. */
  mcpStateStore?: import('../mcp/mcp-state-store.js').McpStateStore;
}

export interface AgentScanResult {
  agent: AgentType;
  version?: string;
  installation: AgentInstallation;
  results: CheckResult[];
  score: number;
  grade: Grade;
}

export interface ScanResult {
  timestamp: string;
  /** VASO version that produced the result (1.3.1+), so a saved report or
   *  baseline says which checks and wording it reflects. */
  vasoVersion?: string;
  host?: string;
  label?: string;
  agents: AgentScanResult[];
  /** Headline posture: worst-case across agents (gated by the weakest agent),
   *  not a mean — see `aggregateScore`. `totalGrade` is its letter grade. */
  totalScore: number;
  totalGrade: Grade;
  /** Mean of per-agent scores — secondary fleet-health/trend metric. Equals
   *  `totalScore` for a single agent; 100 when none are detected. */
  fleetAverage: number;
  summary: {
    critical: number;
    warning: number;
    info: number;
    passed: number;
    total: number;
  };
  /** Set by `scan --diff`: findings compared with the saved baseline. */
  baselineDiff?: BaselineDiffSummary;
  /** MCP servers no detected agent owns (whole-host scans only). */
  hostInventory?: HostInventory;
}

/** `scan --diff` outcome, as carried in reports. Findings are check ids. */
export interface BaselineDiffSummary {
  baselineTimestamp: string;
  newFindings: string[];
  resolvedFindings: string[];
  unchanged: number;
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
  /** Nothing to change: the state the fix sets is already in place (another
   *  fix in the same run got there first). Not a failure. */
  alreadyDone?: boolean;
  /** Not attempted: a dry run, or declined at the prompt. */
  skipped?: boolean;
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
