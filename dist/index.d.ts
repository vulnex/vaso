/**
 * Small JSON key/value store for MCP checks that need to remember state across
 * scans (MCP-027 package-version history, MCP-028 config-drift baseline). Kept
 * separate from the tool-baseline store, whose value shape is tool-specific.
 */
interface McpStateStore {
    load<T = unknown>(key: string): Promise<T | null>;
    save(key: string, value: unknown): Promise<void>;
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
    /** Run with HOME/XDG dirs and cwd pointed at a throwaway directory that is
     *  removed afterwards. Used for agent CLI version queries: several CLIs
     *  initialize state in the user's home on any invocation (Hermes creates
     *  ~/.hermes, Cursor ~/.cursor/cli-config.json, …), and a scan must not
     *  modify what it scans. */
    isolateHome?: boolean;
    /** PATH to resolve the command with and to give it (local providers; a
     *  snapshot answers by command name). Under root, still filtered to
     *  directories no other user can write. */
    path?: string;
}
interface FSProvider {
    readFile(path: string): Promise<string>;
    /**
     * Read raw bytes. LocalFSProvider returns the file's actual bytes, and so
     * does SnapshotFSProvider for snapshots from probe ≥ 1.1.0 (non-UTF-8 files
     * are shipped base64-encoded). From older probes it returns a UTF-8
     * re-encoding of the collected text, where invalid byte sequences were
     * already replaced — byte-level checks must treat those accordingly.
     */
    readBytes(path: string): Promise<Uint8Array>;
    /**
     * The first `n` bytes of a regular file, whatever its size — for checks
     * that only need a header (IOC-007's executable magic). A snapshot answers
     * from the content, or the head the probe shipped for an omitted file.
     * Optional: providers without it are treated as unable to answer.
     */
    readHead?(path: string, n: number): Promise<Uint8Array>;
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
     * path is not a symlink. SnapshotFSProvider answers from the targets the
     * probe recorded (probe ≥ 1.1.0) and throws otherwise.
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
    /** Owner uid/gid of a path (POSIX). Optional; undefined means unknown. */
    ownership?(path: string): Promise<{
        uid: number;
        gid: number;
    } | undefined>;
    /** User-private groups on the scanned host: gid → the one user (uid) it
     *  serves (see core/private-groups.ts). Optional; Linux only. */
    privateGroups?(): Promise<ReadonlyMap<number, number>>;
    exec(cmd: string, args: string[], options?: ExecOptions): Promise<ExecResult>;
    execSync(cmd: string, args: string[], options?: ExecOptions): string;
    /** Look up an environment variable. SnapshotFSProvider reads from the
     *  probe-collected env section; LocalFSProvider reads from process.env. */
    getEnv(key: string): string | undefined;
    readonly platform: Platform;
    /** `'snapshot'` when commands were collected ahead of time by the probe:
     *  `exec` then answers by command name, so running a second copy of a CLI
     *  by full path returns the first copy's output. Absent → treated as live. */
    readonly kind?: 'local' | 'snapshot';
    /** True when the scan runs with root privileges on the scanned host (so
     *  other users' homes are readable). LocalFSProvider checks the process
     *  uid; SnapshotFSProvider reports the probe's privilege. Absent → false. */
    isPrivileged?(): boolean;
    homedir(): string;
    /** Hostname of the machine the scan is running against. LocalFSProvider
     *  returns `os.hostname()`; SnapshotFSProvider returns the value the probe
     *  collected. Used by checks that need to disambiguate per-host state
     *  (e.g. MCP tool-baseline keys when fleet-scanning two hosts whose
     *  configs declare the same server name with no localPath/packageName). */
    hostname(): string;
}

/**
 * The dependencies an MCP server ships with, for MCP-027's dependency arm
 * (advisories against the MCP SDK and other server-side packages).
 *
 * Read from the project around the server's entry file, most exact first:
 * the installed copy (`node_modules/<pkg>/package.json`, a `.venv`
 * dist-info), then the lockfile (package-lock.json, uv.lock, poetry.lock),
 * then the declared range (package.json `dependencies`, requirements*.txt,
 * pyproject.toml). Dev dependencies don't ship and are left out.
 */

interface ServerDependency {
    name: string;
    ecosystem: 'npm' | 'pypi';
    /** Exact version when known (installed or locked). */
    version?: string;
    /** Declared range when no exact version is known. */
    range?: string;
    /** File the version or range was read from. */
    source: string;
    /** Advisories OSV.dev lists for this exact version (`--audit-deps` only). */
    vulnerabilities?: DependencyVulnerability[];
}
interface DependencyVulnerability {
    /** CVE when OSV knows one, else the OSV id (GHSA-…, PYSEC-…). */
    id: string;
    /** The other ids of the same advisory. */
    aliases: string[];
    summary: string;
    severity: Severity;
    fixedVersion?: string;
    reference: string;
}

/**
 * Why a package's source could not be resolved: `npm` (or `tar`) isn't on
 * PATH, `npm pack` failed (unknown package, registry or network error — `code`
 * is npm's error code when it printed one), timed out, or the package holds no
 * JavaScript source to analyze.
 */
type PackageFetchFailure = {
    reason: 'npm-not-found' | 'tar-not-found' | 'timeout' | 'no-source' | 'invalid-spec';
} | {
    reason: 'npm-failed';
    code?: string;
};

interface MCPServerEntry {
    name: string;
    command?: string;
    args?: string[];
    env?: Record<string, string>;
    /** HTTP headers for remote (SSE / streamable-HTTP) servers — commonly carries `Authorization`. */
    headers?: Record<string, string>;
    url?: string;
    transport: 'stdio' | 'sse' | 'streamable-http';
    /** Switched off in its config (`enabled: false`, `disabled: true`, a whole
     *  MCP section off): never launched. Discovery leaves these out unless asked
     *  (`includeDisabled`), so checks never see them. */
    disabled?: boolean;
}
/** Where a config applies: the user's, one project's, or an extension's. */
type MCPConfigScope = 'user' | 'project' | 'extension';
interface MCPConfig {
    source: string;
    filePath: string;
    servers: MCPServerEntry[];
    /** The agents that load this file (discover() only); empty when no detected
     *  agent owns it (VS Code, a bare project mcp.json). */
    agents?: AgentType[];
    /** Absent means user scope. */
    scope?: MCPConfigScope;
    /** The project the config applies to (project scope). */
    projectRoot?: string;
}
interface MCPDiscoveryResult {
    configs: MCPConfig[];
    totalServers: number;
    /** Explicitly given paths (discoverFromPaths) that are missing or not valid JSON/JSONC. */
    unreadable?: string[];
    /** Explicitly given paths that parsed but hold no MCP servers in any known dialect. */
    empty?: string[];
    /** Discovered config files (discover) that exist but could not be read or parsed. */
    loadErrors?: MCPConfigLoadError[];
}
interface MCPConfigLoadError {
    /** The client the file belongs to ("Cursor", "Claude Code", …). */
    source: string;
    filePath: string;
    stage: 'read' | 'parse';
    message: string;
}
interface MCPServerSource {
    serverName: string;
    packageName?: string;
    localPath?: string;
    sourceCode?: string;
    /**
     * Language of `sourceCode`. Python servers (`python3 server.py`, `uv run
     * server.py`) skip the Babel-based analyzers and get the Python sink analyzer
     * instead; absent means JavaScript/TypeScript.
     */
    language?: 'javascript' | 'python';
    /**
     * Text files the server reads at runtime — named in its source and present
     * next to its entry file (a `documents/` folder of RAG content, prompt
     * files). Returned to the model as tool output, so MCP-034 reads them too.
     */
    dataFiles?: MCPDataFile[];
    /** `--resolve-packages`: why the package's source could not be downloaded (no source then). */
    resolveFailure?: PackageFetchFailure;
    /**
     * A local server whose source is there but could not be read (EACCES, the
     * size limits): why. With `sourceCode`, part of it — helper modules — was
     * not read.
     */
    readFailure?: string;
    /**
     * The local server is a compiled binary (a Go/Rust executable): its format.
     * No source then — reported as an inventory note, not a failed read.
     */
    compiledBinary?: string;
    /** Packages the server ships with (its manifest/lockfile/installed copies), for MCP-027. */
    dependencies?: ServerDependency[];
    /**
     * Directory the `// === <file> ===` markers in a multi-file `sourceCode`
     * are relative to — evidence lines in the joined text are mapped back to
     * `<sourceRoot>/<file>` (see mapSourceEvidence).
     */
    sourceRoot?: string;
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
interface MCPDataFile {
    path: string;
    content: string;
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

type Severity = 'critical' | 'warning' | 'info';
type Grade = 'A' | 'B' | 'C' | 'D' | 'F';
type AgentType = 'openclaw' | 'nanoclaw' | 'picoclaw' | 'mcp' | 'ironclaw' | 'nanobot' | 'zeroclaw' | 'nemoclaw' | 'openshell' | 'hermes' | 'lyrie' | 'atomic-agent' | 'claude-code' | 'claude-desktop' | 'chatgpt-desktop' | 'codex' | 'opencode' | 'gemini-cli' | 'qwen-code' | 'copilot-cli' | 'cursor-cli' | 'windsurf' | 'devin' | 'meta-muse' | 'comet' | 'abacus' | 'grok-bot' | 'skill-audit';
type CheckCategory = 'config' | 'skills' | 'ioc' | 'network' | 'runtime' | 'policy' | 'mcp' | 'openclaw' | 'nanoclaw' | 'picoclaw' | 'ironclaw' | 'nanobot' | 'zeroclaw' | 'lyrie' | 'hermes' | 'atomic-agent' | 'openshell' | 'advisory' | 'coding-agent';
declare const AGENT_TYPES: readonly AgentType[];
declare function isScannableAgentType(v: string): v is AgentType;
declare const CHECK_CATEGORIES: readonly CheckCategory[];
/**
 * Coding agents (interactive developer tools) — different threat model from
 * autonomous server frameworks. Used by checks via `excludedAgents` to skip
 * server-only concepts like gateway binding, rate limiting, LaunchAgents, etc.
 */
declare const CODING_AGENTS: AgentType[];
/**
 * Host OS, as `process.platform` reports it. Spelled out (same values as
 * Node's `Platform`) so the published typings don't need @types/node.
 */
type Platform = 'aix' | 'android' | 'darwin' | 'freebsd' | 'haiku' | 'linux' | 'openbsd' | 'sunos' | 'win32' | 'cygwin' | 'netbsd';
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
interface CheckModule {
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
interface ParsedConfig {
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
    /** The skills this installation loads — set by `vaso detect` and `vaso scan`. */
    inventory?: AgentInventory;
}
/**
 * What an installation loads: descriptive, never judged. Names and paths
 * only — a skill's description is masked and shortened, nothing else of a
 * file's content is carried.
 */
interface AgentInventory {
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
interface McpServerItem {
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
interface HostInventory {
    /** MCP servers in files no detected agent owns (VS Code, a bare project mcp.json). */
    mcpServers: McpServerItem[];
    /** The same MCP server configured for several installations, in separate config files. */
    sharedMcpServers?: SharedMcpServer[];
}
/** One MCP server several installations configure: a change to it (or a compromise of it) reaches all of them. */
interface SharedMcpServer {
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
interface SkillsDirInfo {
    path: string;
    exists: boolean;
}
interface SkillItem {
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
interface SkillTreeEntry {
    path: string;
    root: string;
    type: 'directory' | 'file';
    files: number;
    hasCode: boolean;
}
/** One copy of an agent CLI: its path and (when determinable) version. */
interface CliInstall {
    path: string;
    version?: string;
}
interface ScanContext {
    installation: AgentInstallation;
    configs: ParsedConfig[];
    platform: Platform;
    fs: FSProvider;
    skillFiles?: string[];
    /** Files the adapter has declared as security-sensitive (credentials, auth
     *  state, etc.). Used by permission checks to avoid flagging benign config
     *  files. Pre-computed by the engine from `adapter.getCredentialPaths()` —
     *  never for a project installation (credential stores are user-level). */
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
interface BaselineDiffSummary {
    baselineTimestamp: string;
    newFindings: string[];
    resolvedFindings: string[];
    unchanged: number;
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
    readonly platform: Platform;
    /**
     * Linux file names are bytes, not necessarily UTF-8 (`caf\xe9.js`). A
     * listing decodes them as the probe's JSON does — invalid sequences become
     * U+FFFD, so evidence paths match a remote scan — and remembers the raw
     * bytes under that name, so a read of the listed path reaches the file
     * instead of failing silently (a skill could hide code that way).
     */
    private readonly rawPaths;
    /** The bytes to hand the OS for a path this provider listed. */
    private fsPath;
    /** List `dir`, decoding names and remembering raw paths that aren't UTF-8. */
    private list;
    /**
     * A replacement character in a listed name may stand for bytes that aren't
     * UTF-8: list again as bytes (rare) and remember each such name's raw path.
     */
    private rememberRawNames;
    readFile(path: string): Promise<string>;
    readBytes(path: string): Promise<Uint8Array>;
    readHead(path: string, n: number): Promise<Uint8Array>;
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
    ownership(path: string): Promise<{
        uid: number;
        gid: number;
    } | undefined>;
    private privateGroupsCache?;
    privateGroups(): Promise<ReadonlyMap<number, number>>;
    realpath(path: string): Promise<string>;
    readlink(path: string): Promise<string>;
    exec(cmd: string, args: string[], options?: ExecOptions): Promise<ExecResult>;
    execSync(cmd: string, args: string[], options?: ExecOptions): string;
    isPrivileged(): boolean;
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
    /** Collected variables (exact names) whose URL value the probe (newer than 1.4.0)
     *  keeps only up to its origin — path, query and fragment become
     *  placeholders. For endpoint overrides where checks judge the host. */
    envOriginOnly?: string[];
    /** Variables (exact names) recorded only as set or not: the probe (newer than
     *  1.4.0) stores ENV_PRESENT_VALUE when one is non-empty after trimming, and
     *  nothing otherwise — never its value. */
    envPresence?: string[];
}
interface CommandRequest {
    id: string;
    cmd: string;
    args: string[];
    timeout?: number;
    /** Run with a throwaway HOME/XDG dirs and cwd (agent CLI version queries). */
    isolateHome?: boolean;
    /** Run once per item of an earlier command's JSON output (probe ≥ 1.1.0),
     *  substituting `{field}` placeholders in `args`. Each run is stored under its
     *  natural `<cmd> <args>` key, so `fs.exec` with the substituted args finds it. */
    forEach?: CommandForEach;
}
interface CommandForEach {
    /** `id` of an earlier command whose stdout is JSON. */
    from: string;
    /** Top-level key of the array to iterate. */
    array: string;
    /** String fields of each item, substituted for `{field}` in args. */
    fields: string[];
    /** Value for a field an item lacks (null/empty) — e.g. an OpenShell sandbox
     *  listed without a workspace lives in `default` (probe ≥ 1.3.0; older probes skip the item). */
    defaults?: Record<string, string>;
}
interface ProbeSnapshot {
    version: 1;
    /** Build of the probe that collected it (probe ≥ 1.3.1; absent from older probes). */
    probeVersion?: string;
    hostname: string;
    platform: Platform;
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
    /** Symlinks seen in listings and glob matches, path → link target (probe ≥ 1.1.0). */
    symlinks?: Record<string, string>;
    /** Owner [uid, gid] of collected files and directories (probe ≥ 1.1.0). */
    owners?: Record<string, [number, number]>;
    /** User-private groups on the host, gid → uid (probe ≥ 1.1.0, Linux). */
    privateGroups?: Record<string, number>;
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
    /** Why the content was omitted (probe ≥ 1.3.1; `sensitive` ≥ 1.4.0: reached
     *  through a symlink into a credential store or shell startup file). */
    omitted?: 'size' | 'budget' | 'asset' | 'metadata' | 'special' | 'sensitive';
    /** First bytes (base64) of a skill-tree file omitted for size or budget
     *  (probe ≥ 1.3.1) — where an executable header sits: 64 bytes up to 1.4.0,
     *  then 4 KiB or up to a PE stub's header at e_lfanew (≤ 1 MiB). */
    head?: string;
    /** `'base64'` when the file is not valid UTF-8 and `content` holds its bytes
     *  base64-encoded (probe ≥ 1.1.0); absent means UTF-8 text. */
    encoding?: 'base64';
    /** Permission denied (probe ≥ 1.3.1): stat failed (exists false — inside a
     *  chmod-000 directory) or the file can't be opened (exists true, mode set). */
    denied?: boolean;
}
interface CommandOutput {
    stdout: string;
    stderr: string;
    exitCode: number;
}

declare class SnapshotFSProvider implements FSProvider {
    readonly kind: "snapshot";
    readonly platform: Platform;
    private snapshot;
    private indexes;
    constructor(snapshot: ProbeSnapshot);
    readFile(path: string): Promise<string>;
    readBytes(path: string): Promise<Uint8Array>;
    readHead(path: string, n: number): Promise<Uint8Array>;
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
    ownership(path: string): Promise<{
        uid: number;
        gid: number;
    } | undefined>;
    privateGroups(): Promise<ReadonlyMap<number, number>>;
    realpath(path: string): Promise<string>;
    /**
     * Follows the link targets the probe recorded (≥ 1.1.0), component by
     * component like a local realpath — so an npm bin shim resolves into its
     * package and copies dedupe by what they point to. Links the probe never
     * met stay as they are (older snapshots have none).
     */
    private resolveSymlinks;
    readlink(path: string): Promise<string>;
    exec(cmd: string, args: string[], _options?: ExecOptions): Promise<ExecResult>;
    execSync(cmd: string, args: string[], _options?: ExecOptions): string;
    homedir(): string;
    hostname(): string;
    getEnv(key: string): string | undefined;
    /** The probe was asked for this file: it has an entry, even when the file was absent. */
    collected(path: string): boolean;
    get privilege(): PrivilegeInfo;
    /** The probe ran as root (directly or via --sudo). */
    /**
     * A directory the probe saw but could not list: no read bit for anyone and
     * no listing (an unprivileged probe can't read a mode-000 directory, and
     * neither can a local scan by the same user).
     */
    private unlistable;
    /**
     * Under a directory the probe recorded without search (x) permission: a
     * local stat or open of anything there fails with EACCES, existing or not,
     * so the snapshot answers the same instead of ENOENT.
     */
    private behindUnsearchable;
    isPrivileged(): boolean;
    /**
     * Returns true only when the snapshot has an explicit, non-null listing for
     * the given directory. Older probes (and the Go zero-value behaviour) could
     * insert keys with `null` listings when `os.ReadDir` failed for a missing
     * directory; treating those as "exists" produces false-positive agent
     * detections, so they're filtered out here.
     */
    private directoryExists;
    /**
     * The keys of one snapshot map that start with prefix, in the map's own
     * order. A sorted index (built once) makes this a binary search: walking
     * every collected file per lookup cost seconds on a 10k-file snapshot.
     */
    private keysUnder;
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
    getForPlatform(platform: Platform): CheckModule[];
    getApplicable(agent: AgentType, platform: Platform): CheckModule[];
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
    /** filePath is the unreadable directory every attempted config sits behind
     *  (one finding for the directory, not one per file name tried in it). */
    directory?: boolean;
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
    private checkTimeoutMs;
    constructor(adapters: AdapterRegistry, checks: CheckRegistry, fs?: FSProvider, options?: {
        checkTimeoutMs?: number;
    });
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
    /** An installation whose scan failed outside any one check (an internal error). */
    private agentErrorResult;
    private adapterErrorResult;
    scanMCP(mcpConfigs: MCPConfig[], serverSources: MCPServerSource[], options: ScanOptions, 
    /** Discovered MCP config files that could not be read or parsed. */
    loadErrors?: readonly MCPConfigLoadError[]): Promise<ScanResult>;
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
    supportedPlatforms?: Platform[];
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
/**
 * Add a report format. Names already taken — the built-in formats above or
 * another plugin's — are refused, like duplicate checks and adapters: a
 * plugin silently replacing `csv` or `sarif` would change what CI ingests
 * (and drop protections such as CSV formula neutralization).
 */
declare function registerReporter(format: string, factory: () => Reporter): void;

declare const VERSION: string;

export { AGENT_TYPES, type AdapterConfigLoadError, type AdapterDetectionError, type AdapterDetectionResult, AdapterRegistry, type AgentAdapter, type AgentInstallation, type AgentInventory, type AgentScanResult, type AgentType, type BaselineDiffSummary, CHECK_CATEGORIES, CODING_AGENTS, type CheckCategory, type CheckHelpers, type CheckModule, CheckRegistry, type CheckResult, type CliInstall, type CommandOutput, type CommandRequest, type ConfigLoadError, type DefineCheckArgs, type DetectOptions, type DirentInfo, type Evidence, type ExecOptions, type ExecResult, type FSProvider, type FileEntry, type FixResult, type GatewayInfo, type Grade, type HostInventory, LocalFSProvider, type MCPConfig, type MCPDiscoveryResult, type MCPServerEntry, type MCPServerSource, type McpServerItem, type McpStateStore, type ModelRef, type OutputFormat, type OwaspAgenticId, type OwaspMcpId, type ParsedConfig, type PermissionFacts, type PermissionQuery, type Platform, type PrivilegeInfo, type ProbeManifest, type ProbeSnapshot, type Reporter, type ScanContext, ScanEngine, type ScanOptions, type ScanResult, type Severity, type SharedMcpServer, type SkillItem, type SkillTreeEntry, type SkillsDirInfo, SnapshotFSProvider, type ToolBaselineStore, VERSION, type Zone, type ZoneComponent, type ZoneEdge, type ZoneGraph, accessibleByOthers, adapterRegistry, aggregateScore, allAdapters, checkRegistry, computeScore, defineCheck, getReporter, initAdvisoryDatabase, initIOCDatabase, isScannableAgentType, loadConfig, meanScore, posixPermissionFacts, queryPermissions, readableByOthers, registerAllAdapters, registerAllChecks, registerReporter, scoreToGrade, summarizeResults, writableByOthers };
