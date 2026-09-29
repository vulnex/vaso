/**
 * Small JSON key/value store for MCP checks that need to remember state across
 * scans (MCP-027 package-version history, MCP-028 config-drift baseline). Kept
 * separate from the tool-baseline store, whose value shape is tool-specific.
 */
interface McpStateStore {
    load<T = unknown>(key: string): Promise<T | null>;
    save(key: string, value: unknown): Promise<void>;
}

interface MCPServerEntry {
    name: string;
    command?: string;
    args?: string[];
    env?: Record<string, string>;
    /** HTTP headers for remote (SSE / streamable-HTTP) servers — commonly carries `Authorization`. */
    headers?: Record<string, string>;
    url?: string;
    transport: 'stdio' | 'sse' | 'streamable-http';
}
interface MCPConfig {
    source: string;
    filePath: string;
    servers: MCPServerEntry[];
}
interface MCPServerSource {
    serverName: string;
    packageName?: string;
    localPath?: string;
    sourceCode?: string;
    /**
     * Tool definitions extracted from `sourceCode`, populated once by the engine
     * (see `ScanEngine.scanMCP`) so tool-layer checks (MCP-020/024/025) share one
     * extraction pass instead of each re-parsing the source.
     */
    tools?: MCPToolDefinition[];
}
interface MCPToolDefinition {
    name: string;
    description?: string;
    schema?: string;
}

interface ToolBaseline {
    serverName: string;
    identity: string;
    timestamp: string;
    tools: Record<string, string>;
}
interface ToolBaselineStore {
    load(key: string): Promise<ToolBaseline | null>;
    save(key: string, baseline: ToolBaseline): Promise<void>;
}

interface DirentInfo {
    name: string;
    isFile: boolean;
    isDirectory: boolean;
    /**
     * True when the entry is a symbolic link (from an lstat-style read that does
     * not follow the link). `isFile`/`isDirectory` reflect the link itself, not
     * its target, so a symlink to a regular file has all three of `isFile:false`,
     * `isDirectory:false`, `isSymbolicLink:true`. Optional because providers that
     * cannot observe link status (SnapshotFSProvider, test mocks) leave it unset;
     * consumers treat unset as "not a symlink".
     */
    isSymbolicLink?: boolean;
    parentPath?: string;
}
/**
 * Provider-neutral answer to "who besides the owner can touch this path".
 *
 * On POSIX the facts are derived from mode bits (group/world triads). A
 * Windows provider derives them from ACL evaluation instead — grants to
 * Everyone map to the `world*` flags, grants to Users / Authenticated Users
 * to the `group*` flags — so checks written against these facts are
 * platform-neutral without ever seeing win32's fake mode bits.
 */
interface PermissionFacts {
    groupRead: boolean;
    groupWrite: boolean;
    groupExec: boolean;
    worldRead: boolean;
    worldWrite: boolean;
    worldExec: boolean;
    /**
     * Octal permission string like "644" when the facts came from POSIX mode
     * bits; unset when they came from ACLs. Checks embed it in evidence
     * snippets that historically printed the raw mode.
     */
    octal?: string;
    /** Short human description of the source, e.g. `mode 644` or an ACL grant summary. */
    description: string;
}
/**
 * Tri-state permission answer (see devnotes commercial design §3): facts when
 * the provider can genuinely evaluate them, `'unsupported'` when it cannot
 * (e.g. POSIX providers on win32, where mode bits are fake). Checks must
 * treat `'unsupported'` as "cannot evaluate" and skip cleanly — never as
 * "safe" or "unsafe".
 */
type PermissionQuery = PermissionFacts | 'unsupported';
interface ExecResult {
    stdout: string;
    stderr: string;
    exitCode: number;
}
interface ExecOptions {
    timeout?: number;
    encoding?: string;
    cwd?: string;
}
interface FSProvider {
    readFile(path: string): Promise<string>;
    /**
     * Read raw bytes. LocalFSProvider returns the file's actual bytes;
     * SnapshotFSProvider returns a UTF-8 re-encoding of the collected text
     * content, which is best-effort: any bytes the probe couldn't represent
     * as valid UTF-8 were already replaced before reaching the snapshot.
     * Callers doing byte-level checks (e.g. magic-byte anchoring) should
     * treat snapshot results accordingly.
     */
    readBytes(path: string): Promise<Uint8Array>;
    readdir(path: string): Promise<string[]>;
    readdirEntries(path: string, options?: {
        recursive?: boolean;
    }): Promise<DirentInfo[]>;
    access(path: string): Promise<boolean>;
    stat(path: string): Promise<{
        mode: number;
        isFile(): boolean;
        isDirectory(): boolean;
    }>;
    realpath(path: string): Promise<string>;
    /**
     * Return the raw target of a symbolic link without resolving it. Unlike
     * `realpath`, this does not require the target to exist (a dangling symlink
     * to `~/.ssh/authorized_keys` planted by a malicious repo still returns its
     * literal target), and it does not follow multi-hop chains — it reports one
     * link's own target string as stored on disk (may be relative). Throws if the
     * path is not a symlink. SnapshotFSProvider throws (link data isn't collected).
     */
    readlink(path: string): Promise<string>;
    /**
     * Semantic permission query (tri-state — see PermissionQuery). Optional
     * capability: providers that can evaluate real permissions implement it;
     * checks go through `queryPermissions()` in core/permissions.ts, which
     * prefers this method and otherwise falls back to POSIX mode bits from
     * `stat()` — or `'unsupported'` on win32, so mode math is never trusted
     * there. A Windows ACL provider makes win32 answerable by implementing
     * this method.
     */
    permissions?(path: string): Promise<PermissionQuery>;
    exec(cmd: string, args: string[], options?: ExecOptions): Promise<ExecResult>;
    execSync(cmd: string, args: string[], options?: ExecOptions): string;
    /** Look up an environment variable. SnapshotFSProvider reads from the
     *  probe-collected env section; LocalFSProvider reads from process.env. */
    getEnv(key: string): string | undefined;
    readonly platform: NodeJS.Platform;
    /** `'snapshot'` when commands were collected ahead of time by the probe:
     *  `exec` then answers by command name, so running a second copy of a CLI
     *  by full path returns the first copy's output. Absent → treated as live. */
    readonly kind?: 'local' | 'snapshot';
    homedir(): string;
    /** Hostname of the machine the scan is running against. LocalFSProvider
     *  returns `os.hostname()`; SnapshotFSProvider returns the value the probe
     *  collected. Used by checks that need to disambiguate per-host state
     *  (e.g. MCP tool-baseline keys when fleet-scanning two hosts whose
     *  configs declare the same server name with no localPath/packageName). */
    hostname(): string;
}

type Severity = 'critical' | 'warning' | 'info';
type Grade = 'A' | 'B' | 'C' | 'D' | 'F';
type AgentType = 'openclaw' | 'nanoclaw' | 'picoclaw' | 'mcp' | 'ironclaw' | 'nanobot' | 'zeroclaw' | 'nemoclaw' | 'hermes' | 'lyrie' | 'atomic-agent' | 'claude-code' | 'claude-desktop' | 'chatgpt-desktop' | 'codex' | 'opencode' | 'gemini-cli' | 'qwen-code' | 'copilot-cli' | 'cursor-cli' | 'windsurf' | 'devin' | 'meta-muse' | 'comet' | 'skill-audit';
type CheckCategory = 'config' | 'skills' | 'ioc' | 'network' | 'runtime' | 'policy' | 'mcp' | 'openclaw' | 'nanoclaw' | 'picoclaw' | 'ironclaw' | 'nanobot' | 'zeroclaw' | 'lyrie' | 'hermes' | 'atomic-agent' | 'advisory' | 'coding-agent';
declare const AGENT_TYPES: readonly AgentType[];
declare function isScannableAgentType(v: string): v is AgentType;
declare const CHECK_CATEGORIES: readonly CheckCategory[];
/**
 * Coding agents (interactive developer tools) — different threat model from
 * autonomous server frameworks. Used by checks via `excludedAgents` to skip
 * server-only concepts like gateway binding, rate limiting, LaunchAgents, etc.
 */
declare const CODING_AGENTS: AgentType[];
type OutputFormat = 'terminal' | 'json' | 'sarif' | 'markdown' | 'html' | 'csv' | 'junit';
interface Evidence {
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
type OwaspMcpId = 'MCP01' | 'MCP02' | 'MCP03' | 'MCP04' | 'MCP05' | 'MCP06' | 'MCP07' | 'MCP08' | 'MCP09' | 'MCP10';
/** OWASP Agentic AI Top 10 identifier, e.g. 'AAI003' (precize list). Tags checks
 *  so reports can show Agentic AI Top 10 coverage. The list omits deprecated
 *  (AAI004/008/010) and in-development (AAI013/015/016) entries. AAI011
 *  (Untraceability) and AAI014 (Alignment Faking) are runtime/behavioral risks a
 *  static scanner can't observe — they appear in coverage tables as gaps. */
type OwaspAgenticId = 'AAI001' | 'AAI002' | 'AAI003' | 'AAI005' | 'AAI006' | 'AAI007' | 'AAI009' | 'AAI011' | 'AAI012' | 'AAI014';
interface CheckResult {
    id: string;
    name: string;
    category: CheckCategory;
    severity: Severity;
    passed: boolean;
    message: string;
    evidence?: Evidence[];
    fixable?: boolean;
    fixDescription?: string;
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
interface CheckModule {
    id: string;
    name: string;
    category: CheckCategory;
    severity: Severity;
    description: string;
    supportedAgents?: AgentType[];
    excludedAgents?: AgentType[];
    supportedPlatforms?: NodeJS.Platform[];
    owaspMcp?: OwaspMcpId;
    owaspAgentic?: OwaspAgenticId[];
    run(context: ScanContext): Promise<CheckResult>;
    fix?(context: ScanContext): Promise<FixResult>;
}
interface ParsedConfig {
    raw: string;
    format: 'json' | 'yaml' | 'env' | 'toml' | 'unknown';
    filePath: string;
    data: Record<string, unknown>;
}
interface GatewayInfo {
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
interface ModelRef {
    /** Model identifier as it appears in the config (e.g. "claude-opus-4-5", "nvidia/nemotron-3-super-120b-a12b"). */
    id: string;
    /** Provider/router when separable from the id (e.g. "ollama", "anthropic", "nvidia-nim"). */
    provider?: string;
    /** Disambiguator when an agent declares the same model under multiple slots — e.g. nemoclaw sandbox name, openclaw profile. */
    via?: string;
}
interface AgentInstallation {
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
}
/** One copy of an agent CLI: its path and (when determinable) version. */
interface CliInstall {
    path: string;
    version?: string;
}
interface ScanContext {
    installation: AgentInstallation;
    configs: ParsedConfig[];
    platform: NodeJS.Platform;
    fs: FSProvider;
    skillFiles?: string[];
    /** Files the adapter has declared as security-sensitive (credentials, auth
     *  state, etc.). Used by permission checks to avoid flagging benign config
     *  files. Pre-computed by the engine from `adapter.getCredentialPaths()`. */
    credentialPaths?: string[];
    mcpConfigs?: MCPConfig[];
    mcpServerSources?: MCPServerSource[];
    mcpToolBaselineStore?: ToolBaselineStore;
    /** Cross-scan state for MCP-027 (version history) and MCP-028 (config drift).
     *  Defaults to a file-backed store inside each check; injectable for tests. */
    mcpStateStore?: McpStateStore;
}
interface AgentScanResult {
    agent: AgentType;
    version?: string;
    installation: AgentInstallation;
    results: CheckResult[];
    score: number;
    grade: Grade;
}
interface ScanResult {
    timestamp: string;
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
}
interface ScanOptions {
    agentFilter?: string;
    format?: OutputFormat;
    saveBaseline?: boolean;
    diff?: boolean;
    allUsers?: boolean;
}
interface FixResult {
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
interface Zone {
    id: string;
    label: string;
    trustLevel: number;
}
interface ZoneComponent {
    id: string;
    label: string;
    zone: string;
    guardCheckIds?: string[];
}
interface ZoneEdge {
    from: string;
    to: string;
    label?: string;
    kind?: 'data' | 'control' | 'resource' | 'feedback';
    triggerCheckIds?: string[];
}
interface ZoneGraph {
    zones: Zone[];
    components: ZoneComponent[];
    edges: ZoneEdge[];
}

declare class LocalFSProvider implements FSProvider {
    readonly kind: "local";
    readonly platform: NodeJS.Platform;
    readFile(path: string): Promise<string>;
    readBytes(path: string): Promise<Uint8Array>;
    readdir(path: string): Promise<string[]>;
    readdirEntries(path: string, options?: {
        recursive?: boolean;
    }): Promise<DirentInfo[]>;
    access(path: string): Promise<boolean>;
    stat(path: string): Promise<{
        mode: number;
        isFile(): boolean;
        isDirectory(): boolean;
    }>;
    permissions(path: string): Promise<PermissionQuery>;
    realpath(path: string): Promise<string>;
    readlink(path: string): Promise<string>;
    exec(cmd: string, args: string[], options?: ExecOptions): Promise<ExecResult>;
    execSync(cmd: string, args: string[], options?: ExecOptions): string;
    homedir(): string;
    hostname(): string;
    getEnv(key: string): string | undefined;
}

interface ProbeManifest {
    filePaths: string[];
    globPatterns: string[];
    commands: CommandRequest[];
    directoryListings: string[];
    envPrefixes: string[];
    systemPaths?: string[];
    systemDirListings?: string[];
    /** Globs recorded as metadata only (exists + mode, no content) — private
     *  data where checks need permissions, e.g. conversation stores. */
    metadataGlobPatterns?: string[];
}
interface CommandRequest {
    id: string;
    cmd: string;
    args: string[];
    timeout?: number;
}
interface ProbeSnapshot {
    version: 1;
    hostname: string;
    platform: NodeJS.Platform;
    homedir: string;
    timestamp: string;
    privilege: PrivilegeInfo;
    files: Record<string, FileEntry>;
    directories: Record<string, string[]>;
    commandOutputs: Record<string, CommandOutput>;
    env: Record<string, string>;
    /** Permission bits of listed directories and user homes (probe ≥ 1.0.0). */
    directoryModes?: Record<string, number>;
    /** The probe's content budget ran out; later files carry metadata only. */
    truncated?: boolean;
}
interface PrivilegeInfo {
    uid: number;
    username: string;
    isRoot: boolean;
    sudoAvailable: boolean;
    escalated: boolean;
    scannedUsers: string[];
    skippedPaths: string[];
}
interface FileEntry {
    content: string;
    mode: number;
    exists: boolean;
    /** Exists, but content was deliberately not collected (size cap, content
     *  budget, binary asset, or a metadata-only glob). */
    contentOmitted?: boolean;
}
interface CommandOutput {
    stdout: string;
    stderr: string;
    exitCode: number;
}

declare class SnapshotFSProvider implements FSProvider {
    readonly kind: "snapshot";
    readonly platform: NodeJS.Platform;
    private snapshot;
    constructor(snapshot: ProbeSnapshot);
    readFile(path: string): Promise<string>;
    readBytes(path: string): Promise<Uint8Array>;
    readdir(path: string): Promise<string[]>;
    readdirEntries(path: string, options?: {
        recursive?: boolean;
    }): Promise<DirentInfo[]>;
    access(path: string): Promise<boolean>;
    stat(path: string): Promise<{
        mode: number;
        isFile(): boolean;
        isDirectory(): boolean;
    }>;
    /**
     * Tri-state permission answer: real facts for collected files and for
     * directories whose mode the probe recorded; 'unsupported' otherwise, so
     * permission checks skip instead of evaluating an invented mode (a guessed
     * 0o755 made every remote directory look group/world-readable).
     */
    permissions(path: string): Promise<PermissionQuery>;
    realpath(path: string): Promise<string>;
    readlink(path: string): Promise<string>;
    exec(cmd: string, args: string[], _options?: ExecOptions): Promise<ExecResult>;
    execSync(cmd: string, args: string[], _options?: ExecOptions): string;
    homedir(): string;
    hostname(): string;
    getEnv(key: string): string | undefined;
    get privilege(): PrivilegeInfo;
    /**
     * Returns true only when the snapshot has an explicit, non-null listing for
     * the given directory. Older probes (and the Go zero-value behaviour) could
     * insert keys with `null` listings when `os.ReadDir` failed for a missing
     * directory; treating those as "exists" produces false-positive agent
     * detections, so they're filtered out here.
     */
    private directoryExists;
    private hasChildPaths;
    private readdirRecursive;
    private findCommandOutput;
    private argsMatchId;
}

/**
 * Semantic permission queries for checks.
 *
 * Permission-based checks must not do POSIX mode math themselves: mode bits
 * are meaningless on win32 (`fs.stat` reports fake modes), and routing every
 * check through this module is what keeps them honest there. The tri-state
 * contract (facts | 'unsupported') means a platform the provider cannot
 * evaluate yields 'unsupported' — checks skip cleanly instead of reading
 * garbage bits (see the commercial design doc §3: Windows answers arrive via
 * a provider that implements `FSProvider.permissions()` with ACL evaluation,
 * not by making checks platform-neutral over fake modes).
 */
/** Derive semantic permission facts from a POSIX mode word. */
declare function posixPermissionFacts(mode: number): PermissionFacts;
/**
 * Query a path's permission facts through the provider.
 *
 * Preference order:
 *  1. The provider's own `permissions()` capability (a Windows ACL provider,
 *     or any provider that knows better than raw mode bits).
 *  2. `'unsupported'` on win32 — POSIX mode math must never run against
 *     win32's fake modes.
 *  3. POSIX mode bits from `stat()` everywhere else.
 *
 * Propagates `stat()` errors (ENOENT etc.) exactly like the direct
 * `fs.stat()` calls the checks used to make, so existing try/catch
 * flows are unchanged.
 */
declare function queryPermissions(fs: FSProvider, path: string): Promise<PermissionQuery>;
/** Group or world can read (POSIX `mode & 0o044`). */
declare function readableByOthers(f: PermissionFacts): boolean;
/** Group or world can write (POSIX `mode & 0o022`). */
declare function writableByOthers(f: PermissionFacts): boolean;
/** Any non-owner access at all (POSIX `mode & 0o077`) — i.e. NOT owner-only. */
declare function accessibleByOthers(f: PermissionFacts): boolean;

declare class CheckRegistry {
    private checks;
    register(check: CheckModule): void;
    registerAll(checks: CheckModule[]): void;
    getAll(): CheckModule[];
    getByCategory(category: CheckCategory): CheckModule[];
    getForAgent(agent: AgentType): CheckModule[];
    getForPlatform(platform: NodeJS.Platform): CheckModule[];
    getApplicable(agent: AgentType, platform: NodeJS.Platform): CheckModule[];
    count(): number;
}
declare const checkRegistry: CheckRegistry;

interface DetectOptions {
    allUsers?: boolean;
    fs?: FSProvider;
}
interface AgentAdapter {
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
    getModels?(configs: ParsedConfig[], fs?: FSProvider): ModelRef[] | Promise<ModelRef[]>;
    getMemoryFiles?(installDir: string): string[];
    /** `fs` is the provider being scanned (a remote snapshot on --host); adapters
     *  resolving paths from $HOME must use it, not the scanner host's home. */
    getCredentialPaths?(installDir: string, fs?: FSProvider): string[];
    getCLICommand?(): string;
    getProbeManifest?(): ProbeManifest;
    getZoneGraph?(): ZoneGraph;
}

/** A config file that exists but could not be read or parsed. Without this
 *  signal a corrupted config is indistinguishable from an absent one: adapters
 *  catch the loadConfig throw and skip the file, so the scan silently reports
 *  the agent as clean (or not installed) instead of "couldn't inspect it". */
interface ConfigLoadError {
    filePath: string;
    stage: 'read' | 'parse';
    message: string;
}
declare function loadConfig(filePath: string, fs?: FSProvider): Promise<ParsedConfig>;

interface AdapterDetectionError {
    agent: AgentType;
    displayName: string;
    message: string;
}
/** A config file an adapter found but could not read/parse during detect().
 *  Adapters swallow these (a broken file must not abort detection), which
 *  historically made a corrupted config look identical to a clean or absent
 *  one. The registry captures them here so the engine can surface the gap. */
interface AdapterConfigLoadError extends ConfigLoadError {
    agent: AgentType;
    displayName: string;
}
interface AdapterDetectionResult {
    installations: AgentInstallation[];
    errors: AdapterDetectionError[];
    configLoadErrors: AdapterConfigLoadError[];
}
declare class AdapterRegistry {
    private adapters;
    register(adapter: AgentAdapter): void;
    detectAllDetailed(options?: DetectOptions): Promise<AdapterDetectionResult>;
    detectAll(options?: DetectOptions): Promise<AgentInstallation[]>;
    getAdapters(): AgentAdapter[];
    getAdapter(agent: AgentType): AgentAdapter | undefined;
}
declare const adapterRegistry: AdapterRegistry;

declare class ScanEngine {
    private adapters;
    private checks;
    private fs;
    constructor(adapters: AdapterRegistry, checks: CheckRegistry, fs?: FSProvider);
    scan(options: ScanOptions): Promise<ScanResult>;
    private scanAgent;
    /** Surface config files that exist but could not be read/parsed during
     *  detection. Adapters swallow those failures (a broken file must not abort
     *  detection), which used to make a corrupted config indistinguishable from
     *  a clean or absent one. Each failure becomes an `errored` result — the
     *  same partial-scan channel as thrown checks — attached to the agent it
     *  belongs to, or to a synthetic entry when the broken config prevented the
     *  agent from being detected at all. */
    private foldConfigLoadErrors;
    private adapterErrorResult;
    scanMCP(mcpConfigs: MCPConfig[], serverSources: MCPServerSource[], options: ScanOptions): Promise<ScanResult>;
    scanSkill(skillPath: string, skillFiles: string[], options: ScanOptions): Promise<ScanResult>;
    private emptyResult;
}

declare function computeScore(results: CheckResult[]): number;
/**
 * Headline score across multiple agents: worst-case, not mean.
 *
 * A security posture is gated by its weakest agent — one wide-open agent is a
 * real exposure regardless of how many others are clean. A mean has the wrong
 * failure mode here: it grows *more* reassuring as clean agents are added, so it
 * can bury a critical finding in a large fleet. The mean is still reported, but
 * as a secondary fleet-health metric (`meanScore` / `ScanResult.fleetAverage`),
 * never as the headline. With no agents detected there is nothing to fault, so
 * the posture is a clean 100.
 */
declare function aggregateScore(scores: number[]): number;
/** Mean of per-agent scores — fleet-health/trend metric, not the headline. */
declare function meanScore(scores: number[]): number;
declare function scoreToGrade(score: number): Grade;
declare function summarizeResults(results: CheckResult[]): {
    critical: number;
    warning: number;
    info: number;
    passed: number;
    total: number;
};

/** Every built-in adapter, in registration order. */
declare const allAdapters: AgentAdapter[];
/** Register every built-in adapter into the shared adapterRegistry —
 *  the adapter-side counterpart of registerAllChecks(). */
declare function registerAllAdapters(): void;

declare function registerAllChecks(): void;

interface CheckHelpers {
    /**
     * Build a result with the module's id/name/category. Severity defaults to
     * the module-declared severity but can be overridden (for checks like
     * MCP-008 that escalate based on what they found).
     */
    result(args: {
        passed: boolean;
        message: string;
        evidence?: Evidence[];
        severity?: Severity;
        fixable?: boolean;
        fixDescription?: string;
    }): CheckResult;
    /**
     * Build from an evidence array. `passed` inferred from `evidence.length === 0`,
     * message templated from `passed`/`failed` strings. Empty evidence returns
     * `evidence: undefined` (not `[]`) to match downstream conventions.
     * When every evidence item is `mitigated`, severity drops to 'info'.
     */
    fromEvidence(evidence: Evidence[], opts: {
        passed: string;
        failed: (count: number) => string;
        severity?: Severity;
        fixable?: boolean;
        fixDescription?: string;
    }): CheckResult;
    /**
     * Shortcut for early-return when a precondition is missing
     * (e.g. SKL-001 with no skills directory). Always passes.
     */
    passed(message: string): CheckResult;
}
interface DefineCheckArgs {
    id: string;
    name: string;
    category: CheckCategory;
    severity: Severity;
    description: string;
    supportedAgents?: AgentType[];
    excludedAgents?: AgentType[];
    supportedPlatforms?: NodeJS.Platform[];
    run(ctx: ScanContext, h: CheckHelpers): Promise<CheckResult>;
    fix?(ctx: ScanContext): Promise<FixResult>;
}
declare function defineCheck(args: DefineCheckArgs): CheckModule;

/**
 * Initialize the IOC database by loading any cached feed and merging
 * with bundled data. Call once at startup. Safe to call multiple times
 * (idempotent after first call unless reloadIOCDatabase() is called).
 */
declare function initIOCDatabase(): Promise<void>;

declare function initAdvisoryDatabase(): Promise<void>;

interface Reporter {
    readonly format: string;
    render(result: ScanResult): string;
}

declare function getReporter(format: string): Reporter;
declare function registerReporter(format: string, factory: () => Reporter): void;

declare const VERSION: string;

export { AGENT_TYPES, type AdapterConfigLoadError, type AdapterDetectionError, type AdapterDetectionResult, AdapterRegistry, type AgentAdapter, type AgentInstallation, type AgentScanResult, type AgentType, CHECK_CATEGORIES, CODING_AGENTS, type CheckCategory, type CheckModule, CheckRegistry, type CheckResult, type CliInstall, type DetectOptions, type DirentInfo, type Evidence, type ExecOptions, type ExecResult, type FSProvider, type FixResult, type GatewayInfo, type Grade, LocalFSProvider, type ModelRef, type OutputFormat, type OwaspAgenticId, type OwaspMcpId, type ParsedConfig, type PermissionFacts, type PermissionQuery, type Reporter, type ScanContext, ScanEngine, type ScanOptions, type ScanResult, type Severity, SnapshotFSProvider, VERSION, type Zone, type ZoneComponent, type ZoneEdge, type ZoneGraph, accessibleByOthers, adapterRegistry, aggregateScore, allAdapters, checkRegistry, computeScore, defineCheck, getReporter, initAdvisoryDatabase, initIOCDatabase, isScannableAgentType, loadConfig, meanScore, posixPermissionFacts, queryPermissions, readableByOthers, registerAllAdapters, registerAllChecks, registerReporter, scoreToGrade, summarizeResults, writableByOthers };
