# VASO Development Guide

Technical reference for extending VASO with new security checks, agent adapters, output reporters, and analyzers.

## Architecture Overview

```
src/
  cli.ts                    Entry point — registers adapters, checks, wires commands
  index.ts                  Library entry (programmatic API) → dist/index.js + .d.ts
  core/
    types.ts                All shared interfaces
    engine.ts               ScanEngine — orchestrates detection + checks + scoring
    check-registry.ts       CheckRegistry — stores and queries check modules
    config-loader.ts        Parses JSON, YAML, TOML, .env files into ParsedConfig
    scoring.ts              Score computation and grading
    baseline.ts             Differential scanning (save/load/diff)
    patterns.ts             Shared credential detection regex patterns
    fs-provider.ts          FSProvider interface — abstraction over filesystem
    local-fs-provider.ts    LocalFSProvider — direct host filesystem access
    snapshot-fs-provider.ts SnapshotFSProvider — serves files from a probe snapshot
    snapshot-types.ts       Probe manifest + snapshot data shapes
    default-zone-graph.ts   4-zone fallback ZoneGraph for adapters without one
    zone-graph-validator.ts CI gate — fails init if a graph names an unknown check ID
    utils.ts                Shared helpers (e.g. getAllSkillsDirs)
    debug.ts                --debug flag plumbing
  adapters/
    adapter.ts              AgentAdapter interface
    index.ts                allAdapters array + registerAllAdapters()
    registry.ts             AdapterRegistry — parallel agent detection
    cli-installs.ts         discoverCliInstalls() — every copy of a CLI (PATH, nvm/fnm/asdf/mise/volta/n, retained versions)
    openclaw.ts             OpenClaw adapter
    nanoclaw.ts             NanoClaw adapter
    picoclaw.ts             PicoClaw adapter
    ironclaw.ts             IronClaw adapter
    nanobot.ts              Nanobot adapter
    zeroclaw.ts             ZeroClaw adapter
    nemoclaw.ts             NemoClaw adapter
    openshell.ts            NVIDIA OpenShell adapter
    hermes.ts               Hermes adapter
    lyrie.ts                Lyrie adapter
    atomic-agent.ts         Atomic Agent adapter
    claude-code.ts          Claude Code CLI adapter
    claude-desktop.ts       Claude Desktop / Cowork adapter
    chatgpt-desktop.ts      ChatGPT Desktop adapter
    codex.ts                Codex adapter
    opencode.ts             OpenCode adapter
    gemini.ts               Gemini CLI adapter
    qwen-code.ts            Qwen Code adapter
    copilot-cli.ts          GitHub Copilot CLI adapter
    cursor-cli.ts           Cursor CLI/IDE adapter
    windsurf.ts             Windsurf / Devin Desktop adapter
    devin.ts                Devin CLI adapter
    abacus.ts               Abacus.AI CLI / AbacusAI Desktop adapter
    meta-muse.ts            Meta Muse adapter
    comet.ts                Perplexity Comet adapter
  checks/
    index.ts                registerAllChecks() — wires all categories
    config/                 24 configuration checks (CFG-*)
    skills/                 13 skill code analysis checks (SKL-*)
    ioc/                    8 IOC matching checks (IOC-*)
    network/                5 network checks (NET-*)
    runtime/                5 runtime checks (RUN-*)
    policy/                 5 policy checks (POL-*)
    mcp/                    35 MCP server security checks (MCP-*)
    advisory/               5 advisory/CVE checks (ADV-*)
    openclaw/               7 OpenClaw-specific (OC-*)
    nanoclaw/               5 NanoClaw-specific (NC-*)
    picoclaw/               7 PicoClaw-specific (PCL-*)
    ironclaw/               14 IronClaw-specific (IC-*)
    nanobot/                12 Nanobot-specific (NB-*)
    zeroclaw/               16 ZeroClaw-specific (ZC-*)
    lyrie/                  20 Lyrie-specific (LY-*)
    hermes/                 10 Hermes-specific (HM-*)
    atomic-agent/           11 Atomic Agent-specific (AT-*)
    openshell/              14 NVIDIA OpenShell-specific (OSH-*)
    claude-code/            12 Claude Code-specific (CC-*)
    claude-desktop/         10 Claude Desktop-specific (CD-*)
    chatgpt-desktop/        6 ChatGPT Desktop-specific (CG-*)
    codex/                  10 Codex-specific (CDX-*)
    opencode/               12 OpenCode-specific (OPC-*)
    gemini-cli/             11 Gemini CLI-specific (GEM-*)
    qwen-code/              10 Qwen Code-specific (QC-*)
    copilot-cli/            9 Copilot CLI-specific (GHC-*)
    cursor-cli/             14 Cursor CLI/IDE-specific (CUR-*)
    windsurf-app/           8 Windsurf / Devin Desktop-specific (WS-*)
    devin/                  10 Devin CLI-specific (DEV-*)
    abacus/                 15 Abacus.AI CLI/Desktop-specific (ABA-*)
    meta-muse/              3 Meta Muse-specific (MM-*)
    comet/                  2 Perplexity Comet-specific (PC-*)
  analyzers/
    ast-analyzer.ts         Babel-based AST analysis with data flow tracing
    pattern-engine.ts       Regex pattern matching engine (SECURITY_PATTERNS)
    entropy.ts              Shannon entropy for obfuscation detection
    js-parse.ts             Shared Babel parse cache; splits --resolve-packages concatenations per file
    tool-input-taint.ts     MCP-005/009: tool input traced through variables/call sites into code, command & fs-path sinks
    tool-result-flow.ts     MCP-007: fetched/read content traced into tool-result text blocks (JS AST; Python tool functions)
    python-sinks.ts         MCP-004/005 for Python servers (line-level: subprocess, eval, path traversal)
    string-literals.ts      String contents by line (MCP-034 judges text, not code)
    source-secrets.ts       MCP-003: credentials hardcoded in server source (masked evidence)
  mcp/
    types.ts                MCP-specific interfaces (MCPServerEntry, MCPConfig, etc.)
    discovery.ts            MCPDiscovery — auto-discovers MCP configs across tools
    source-resolver.ts      Resolves MCP server source (node/python/uv, --source paths, data files)
    remote-endpoint.ts      Remote URL of a server entry, direct or via mcp-remote / supergateway
    source-segments.ts      Statement-sized units of (possibly minified) source for regex checks
    oauth-context.ts        OAuth context tests shared by MCP-013/018
    package-name.ts         Package/spec name normalization (bare name, service core) for MCP-008
    package-fetcher.ts      Opt-in npm tarball download for --resolve-packages (never executed)
    server-dependencies.ts  Dependencies a server ships (installed > lockfile > declared; npm + PyPI) for MCP-027
    osv-audit.ts            Opt-in OSV.dev lookup of those dependency versions (--audit-deps)
    tool-baseline.ts        ToolBaselineStore — MCP-020 rug-pull baseline persistence
  ioc/
    database.ts             Bundled threat intelligence data
    updater.ts              Ed25519-signed remote feed fetcher
    feed-types.ts           IOC feed data types
    public-key.ts           Pinned Ed25519 verification key
    typosquat.ts            Levenshtein distance for typosquatting
  advisory/
    database.ts             Bundled CVE/advisory data + ADV-* check support
    library-advisories.ts   Bundled npm/PyPI library advisories + always-deprecated npm packages (MCP-027)
    updater.ts              Signed advisory feed fetcher
  remediation/
    engine.ts               RemediationEngine — backup + fix orchestration
    config-writer.ts        Format-aware writers (JSON/YAML/TOML/ENV)
    prompt.ts               Interactive TUI prompt (y/n/a/q) for per-fix confirmation
    rollback.ts             Restore from ~/.vaso/backups/
  reporting/
    reporter.ts             Reporter interface
    index.ts                Reporter factory + registration
    terminal.ts             Chalk-based terminal output
    json.ts                 JSON output
    sarif.ts                SARIF v2.1.0 output (GitHub Code Scanning)
    markdown.ts             Markdown tables output
    html.ts                 Self-contained HTML (XSS-safe)
    csv.ts                  CSV — one row per finding (SIEM ingestion)
    junit.ts                JUnit XML (CI test-result reporters)
  commands/
    scan.ts                 vaso scan handler
    detect.ts               vaso detect handler
    fix.ts                  vaso fix handler
    visualize.ts            vaso visualize handler (PRD-006 USecVisLib emission)
    update.ts               vaso update handler
    mcp.ts                  vaso mcp scan/list handler
    skill-audit.ts          vaso skill audit handler
    user-plugin.ts          vaso ext list/info handler
    rules.ts                vaso rules list/validate/init handler
    probe.ts                vaso probe manifest/validate handler
  visualizations/           USecVisLib config emitters (attack-tree, privilege-gradient, component)
  user-plugins/             Drop-in loader for ~/.vaso/plugins/*.{js,mjs}
  rules/                    Declarative YAML rules engine scaffolding (WIP — design only, not yet implemented)
  transport/                SSH multi-host orchestrator (worker pool + retries)
```

## Scan Engine Flow

### Agent Scan (`vaso scan`)

```
1. cli.ts registers adapters and checks at startup
2. Engine picks an FSProvider:
   — LocalFSProvider for local scans
   — SnapshotFSProvider when --snapshot or --host is passed
3. ScanEngine.scan() calls AdapterRegistry.detectAll(fs)
   — each adapter probes the filesystem in parallel (Promise.allSettled)
   — returns AgentInstallation[] (plural — a single host can have multiple
     installs of the same agent, e.g. per-user OpenClaw profiles)
4. For each installation, engine pre-resolves skill files via
   getAllSkillsDirs() and builds a ScanContext (carrying fs, configs,
   skillFiles, credentialPaths, optional mcpConfigs/mcpServerSources)
5. CheckRegistry.getApplicable(agent, platform) filters relevant checks
6. All applicable checks run concurrently (Promise.allSettled)
7. Results are scored (computeScore), graded (scoreToGrade), summarized
8. Reporter renders the ScanResult into the requested format
```

Remote scans push a static Go probe (`vaso-probe`) to each host over SSH,
collect a snapshot, and run the same engine against a SnapshotFSProvider.
Behaviour is identical end-to-end — checks never know whether they're
reading from a real disk or from a frozen probe snapshot.

### MCP Scan (`vaso mcp scan`)

```
1. MCPDiscovery.discover() probes known config locations for MCP configs
   — Claude Desktop, Claude Code, Cursor, Windsurf, Devin CLI (global +
     project .devin/mcp_config[.local].json), Atomic Agent, Nanobot,
     PicoClaw, Lyrie, VS Code, project-level
2. resolveServerSources() resolves local paths to server source code
3. ScanEngine.scanMCP() builds a ScanContext with mcpConfigs +
   mcpServerSources + (optionally) mcpToolBaselineStore for MCP-020
4. MCP checks (MCP-001 to MCP-035) run against the context
5. Results are scored, graded, and rendered as with agent scans
```

### Skill Audit (`vaso skill audit <path>`)

```
1. Command handler validates path exists and is a directory
2. getSkillFiles(path) discovers code files (.js/.ts/.py/.sh etc.)
3. ScanEngine.scanSkill() builds a synthetic ScanContext:
   — agent: 'skill-audit', installDir/skillsDir: the skill path
   — configFiles: [] (no configs), skillFiles: discovered files
4. Only skills + IOC category checks run (config/network/runtime skipped)
5. Results are scored, graded, and rendered as with agent scans
```

## Core Interfaces

All interfaces are defined in `src/core/types.ts`.

### CheckModule

Every security check implements this interface:

```typescript
interface CheckModule {
  id: string;                              // e.g. 'CFG-001', 'SKL-003', 'LY-018'
  name: string;                            // Human-readable name
  category: CheckCategory;                 // one of 19 categories — see src/core/types.ts
  severity: Severity;                      // 'critical' | 'warning' | 'info'
  description: string;                     // What this check does

  supportedAgents?: AgentType[];           // Omit = all agents
  excludedAgents?: AgentType[];            // Skip these agents — commonly CODING_AGENTS
                                           //   for server-only concerns like gateway binding
  supportedPlatforms?: NodeJS.Platform[];  // Omit = all platforms

  run(context: ScanContext): Promise<CheckResult>;
  fix?(context: ScanContext): Promise<FixResult>;  // Optional auto-fix
}
```

`CheckCategory` is the union: `'config' | 'skills' | 'ioc' | 'network' | 'runtime' | 'policy' | 'mcp' | 'openclaw' | 'nanoclaw' | 'picoclaw' | 'ironclaw' | 'nanobot' | 'zeroclaw' | 'lyrie' | 'hermes' | 'atomic-agent' | 'openshell' | 'advisory' | 'coding-agent'`. `AgentType` is similarly defined in `src/core/types.ts` — re-check the source rather than relying on a frozen list here.

### ScanContext

Passed to every check's `run()` method:

```typescript
interface ScanContext {
  installation: AgentInstallation;       // Detected agent info
  configs: ParsedConfig[];               // All parsed config files
  platform: NodeJS.Platform;             // 'darwin' | 'linux' | 'win32'
  fs: FSProvider;                        // ALWAYS read host state through this —
                                         //   never call homedir(), process.env, fs/promises
                                         //   directly. Snapshot scans depend on it.
  skillFiles?: string[];                 // Pre-resolved skill file paths
  credentialPaths?: string[];            // Adapter-declared sensitive paths
                                         //   (used by permission checks to avoid FPs)
  mcpConfigs?: MCPConfig[];              // Discovered MCP server configs
  mcpServerSources?: MCPServerSource[];  // Resolved MCP server source code
  mcpToolBaselineStore?: ToolBaselineStore;  // Injectable MCP-020 baseline
}
```

The `fs` field is load-bearing for remote/snapshot scans. Checks that hard-coded `os.homedir()`, `process.env`, or `node:fs/promises` produced host-dependent results when scanning remote targets — those were systematically rewritten to flow through `ctx.fs.homedir()`, `ctx.fs.getEnv()`, `ctx.fs.readFile()` etc. during the v0.4.1 correctness sweep. New checks must follow that pattern.

### CheckResult

Returned by every check:

```typescript
interface CheckResult {
  id: string;
  name: string;
  category: CheckCategory;
  severity: Severity;
  passed: boolean;               // true = no issue found
  message: string;               // Human-readable finding or pass message
  evidence?: Evidence[];          // File locations and code snippets
  fixable?: boolean;             // true if auto-fix is available
  fixDescription?: string;       // What the fix does
}
```

### Evidence

Points to the exact location of a finding:

```typescript
interface Evidence {
  file: string;       // Absolute file path
  line?: number;       // 1-based line number
  snippet?: string;    // Relevant code/config line
  detail?: string;     // Additional context
}
```

### AgentAdapter

Each agent framework implements this interface:

```typescript
interface AgentAdapter {
  readonly agent: AgentType;        // see src/core/types.ts for the full union
  readonly displayName: string;     // e.g. 'OpenClaw', 'Claude Code', 'ChatGPT Desktop'

  // detect() returns an ARRAY — a single host can have multiple installs of the
  // same agent (per-user profiles, multiple project-level configs, etc.). Empty
  // array means "not installed".
  detect(options?: DetectOptions): Promise<AgentInstallation[]>;

  getConfigPaths(): string[];
  getSkillsDir(installDir: string): string | undefined;
  getGatewayInfo(config: Record<string, unknown>): GatewayInfo | undefined;

  // Optional hooks — adapters opt in as needed:
  getModels?(configs: ParsedConfig[], fs?: FSProvider): ModelRef[] | Promise<ModelRef[]>;
  getMemoryFiles?(installDir: string): string[];
  getCredentialPaths?(installDir: string): string[];
  getCLICommand?(): string;
  getProbeManifest?(): ProbeManifest;  // What to collect for SSH/snapshot scans
  getZoneGraph?(): ZoneGraph;          // Privilege-gradient model for vaso visualize
}
```

`detect()` receives a `DetectOptions` that carries an `fs?: FSProvider`; adapters must read through it so snapshot scans work. `getProbeManifest()` declares the files, globs, command outputs, and directory listings the static Go probe should collect on a remote target — it's how a new adapter becomes scannable over SSH without modifying the probe.

### Reporter

Output format renderers implement this:

```typescript
interface Reporter {
  readonly format: string;
  render(result: ScanResult): string;
}
```

---

## Adding a New Check

### 1. Choose an ID and Category

IDs follow the pattern `<PREFIX>-<NNN>`. To find the next free ID in any prefix, grep the source — frozen tables in docs drift fast:

```bash
grep -hE "^\s*id:\s*'[A-Z]+-[0-9]+'" src/checks/*/*.ts \
  | sed -E "s/.*id:\s*'([A-Z]+)-([0-9]+)'.*/\1 \2/" \
  | sort -k1,1 -k2,2n | uniq | tail -n +1
```

Current prefix landscape (one prefix per directory under `src/checks/`):

| Category directory | Prefix | Typical scope |
|--------------------|--------|---------------|
| `config/` | CFG | Generic config concerns (binding, TLS, perms, sandbox, auth) |
| `skills/` | SKL | Static analysis of skill code (eval, exfil, obfuscation) |
| `ioc/` | IOC | IOC database matches (C2 IPs, hashes, publishers) |
| `network/` | NET | Network-level posture (port scan, WS origin) |
| `runtime/` | RUN | Host-runtime hardening (LaunchAgents, cron, Docker) |
| `policy/` | POL | Approval policy, redaction, credential perms |
| `mcp/` | MCP | MCP OAuth, transport, tool-flow, rug-pull, source heuristics |
| `advisory/` | ADV | Version-aware CVE detection |
| `openclaw/` | OC | OpenClaw-specific |
| `nanoclaw/` | NC | NanoClaw-specific |
| `picoclaw/` | PCL | PicoClaw-specific |
| `ironclaw/` | IC | IronClaw-specific |
| `nanobot/` | NB | Nanobot-specific |
| `zeroclaw/` | ZC | ZeroClaw-specific |
| `lyrie/` | LY | Lyrie-specific |
| `hermes/` | HM | Hermes-specific |
| `atomic-agent/` | AT | Atomic Agent-specific |
| `openshell/` | OSH | NVIDIA OpenShell-specific |
| `claude-code/` | CC | Claude Code CLI-specific |
| `claude-desktop/` | CD | Claude Desktop / Cowork-specific |
| `chatgpt-desktop/` | CG | ChatGPT Desktop-specific |
| `codex/` | CDX | Codex-specific |
| `opencode/` | OPC | OpenCode-specific |
| `gemini-cli/` | GEM | Gemini CLI-specific |
| `qwen-code/` | QC | Qwen Code-specific |
| `copilot-cli/` | GHC | GitHub Copilot CLI-specific |
| `cursor-cli/` | CUR | Cursor CLI/IDE-specific |
| `windsurf-app/` | WS | Windsurf / Devin Desktop-specific |
| `devin/` | DEV | Devin CLI-specific |
| `abacus/` | ABA | Abacus.AI CLI / AbacusAI Desktop-specific |
| `meta-muse/` | MM | Meta Muse-specific |
| `comet/` | PC | Perplexity Comet-specific |

The per-product coding-agent and desktop-app directories (`claude-code/` through `comet/`) all use the single `coding-agent` category.

### 2. Create the Check File

Create `src/checks/<category>/<id>.ts`. Example for a new config check:

```typescript
// src/checks/config/cfg-025-example.ts
import type { CheckModule, ScanContext, CheckResult } from '../../core/types.js';

export const cfg025: CheckModule = {
  id: 'CFG-025',
  name: 'Insecure Log Level',
  category: 'config',
  severity: 'warning',
  description: 'Check if debug logging is enabled in production, which may leak sensitive data',

  // Optional: scope the check.
  //   supportedAgents: ['openclaw'],         // Only run on these
  //   excludedAgents: CODING_AGENTS,         // Skip Claude Code / Codex / etc.
  //                                          //   for server-only concerns
  //   supportedPlatforms: ['linux', 'darwin'],

  async run(ctx: ScanContext): Promise<CheckResult> {
    const evidence = [];

    for (const config of ctx.configs) {
      const logLevel = config.data.logLevel ?? config.data.LOG_LEVEL;

      if (logLevel === 'debug' || logLevel === 'trace') {
        evidence.push({
          file: config.filePath,
          detail: `Log level set to "${logLevel}" — may expose sensitive data`,
        });
      }
    }

    return {
      id: 'CFG-025',
      name: 'Insecure Log Level',
      category: 'config',
      severity: 'warning',
      passed: evidence.length === 0,
      message: evidence.length === 0
        ? 'Log level is not set to debug/trace'
        : 'Debug logging enabled — may leak sensitive data in logs',
      evidence: evidence.length > 0 ? evidence : undefined,
    };
  },
};
```

### 3. Register the Check

Add the export to the category index file. For config checks, edit `src/checks/config/index.ts`:

```typescript
import { cfg025 } from './cfg-025-example.js';

export const configChecks: CheckModule[] = [
  // ... existing checks
  cfg025,
];
```

All category index files are imported by `src/checks/index.ts`, which calls `registerAllChecks()` at startup. No changes needed there unless you add a new category.

### 4. Add a Fixable Check (Optional)

Add a `fix()` method and mark the result as `fixable: true`:

```typescript
export const cfg025: CheckModule = {
  // ... id, name, category, severity, description

  async run(ctx: ScanContext): Promise<CheckResult> {
    // ... detection logic
    return {
      // ...
      fixable: true,
      fixDescription: 'Set log level to "warn"',
    };
  },

  async fix(ctx: ScanContext): Promise<FixResult> {
    // Use ctx.fs (or the format-aware writers in src/remediation/config-writer.ts).
    // Never call node:fs/promises directly — fixes must respect the same
    // FSProvider abstraction the rest of the engine uses.
    for (const config of ctx.configs) {
      if (config.data.logLevel === 'debug' || config.data.logLevel === 'trace') {
        config.data.logLevel = 'warn';
        await ctx.fs.writeFile(config.filePath, JSON.stringify(config.data, null, 2));
        return { checkId: 'CFG-025', applied: true, message: 'Log level set to warn' };
      }
    }
    return { checkId: 'CFG-025', applied: false, message: 'No config to fix' };
  },
};
```

The `RemediationEngine` handles backups automatically before calling `fix()`.

### 5. Write Tests

Create or extend a test file. Config checks share `src/checks/config/config-checks.test.ts`. For a new category, create a new test file:

```typescript
import { describe, it, expect } from 'vitest';
import { cfg025 } from './cfg-025-example.js';
import type { ScanContext } from '../../core/types.js';
import { LocalFSProvider } from '../../core/local-fs-provider.js';

function makeContext(configData: Record<string, unknown>): ScanContext {
  return {
    installation: { agent: 'openclaw', installDir: '/tmp', configFiles: [] },
    configs: [{
      raw: JSON.stringify(configData),
      format: 'json',
      filePath: '/tmp/config.json',
      data: configData,
    }],
    platform: 'linux',
    fs: new LocalFSProvider(),  // Or a stub for snapshot-style tests
  };
}

describe('CFG-025 Insecure Log Level', () => {
  it('fails when log level is debug', async () => {
    const ctx = makeContext({ logLevel: 'debug' });
    const result = await cfg025.run(ctx);
    expect(result.passed).toBe(false);
    expect(result.severity).toBe('warning');
  });

  it('passes when log level is warn', async () => {
    const ctx = makeContext({ logLevel: 'warn' });
    const result = await cfg025.run(ctx);
    expect(result.passed).toBe(true);
  });

  it('passes when log level is not set', async () => {
    const ctx = makeContext({});
    const result = await cfg025.run(ctx);
    expect(result.passed).toBe(true);
  });
});
```

Run tests:

```bash
# All tests
npm test

# Single file
npx vitest run src/checks/config/config-checks.test.ts
```

### Skill Check Pattern

Skill checks scan source code files. The scan engine pre-resolves skill files via `getAllSkillsDirs(installation)` and exposes them as `ctx.skillFiles` — read them through `ctx.fs.readFile()`, never directly. Then dispatch to the AST analyzer or pattern engine:

```typescript
import { analyzeCode } from '../../analyzers/ast-analyzer.js';
import { scanWithPatterns } from '../../analyzers/pattern-engine.js';

for (const filePath of ctx.skillFiles ?? []) {
  const code = await ctx.fs.readFile(filePath);

  // AST-based (data flow, eval/exec, network calls, fs access):
  const flows = analyzeCode(code, filePath);
  const exfilFlows = flows.filter(f => f.type === 'source-to-sink');

  // Pattern-based (regex matching). scanWithPatterns(code, rules?) — rules
  // defaults to SECURITY_PATTERNS. Filter the rule set yourself if you want
  // only a subset of categories:
  const reverseShellRules = SECURITY_PATTERNS.filter(r => r.category === 'reverse-shell');
  const matches = scanWithPatterns(code, reverseShellRules);
}
```

### IOC Check Pattern

IOC checks compare against the bundled threat database:

```typescript
import { getIOCDatabase } from '../../ioc/database.js';

const db = getIOCDatabase();
// db.c2Ips, db.maliciousDomains, db.fileHashes, db.maliciousPublishers, etc.
```

### MCP Check Pattern

MCP checks operate on discovered MCP server configurations and optionally their resolved source code. Use `ctx.mcpConfigs` for config-level checks and `ctx.mcpServerSources` for source code analysis:

```typescript
// Config-level check (e.g. transport security, credential exposure):
for (const config of ctx.mcpConfigs ?? []) {
  for (const server of config.servers) {
    if (server.transport === 'sse' && server.url && !server.url.startsWith('https://')) {
      evidence.push({
        file: config.filePath,
        detail: `Server "${server.name}" uses insecure SSE transport`,
      });
    }
  }
}

// Source-level check (e.g. tool injection, data exfiltration):
for (const source of ctx.mcpServerSources ?? []) {
  if (!source.sourceCode) continue;
  const flows = analyzeCode(source.sourceCode, source.localPath ?? source.serverName);
  // ... analyze data flows
}
```

Use `src/core/patterns.ts` for shared credential detection regexes (OpenAI, Anthropic, AWS, GitHub, GitLab, Slack keys, and private keys).

---

## Adding a New Agent Adapter

### 1. Extend AgentType

Add the new agent type to the `AgentType` union and the `AGENT_TYPES` runtime array in `src/core/types.ts`. The example below uses a hypothetical `'megaclaw'`:

```typescript
// In src/core/types.ts — extend BOTH the type union and the runtime array:
export type AgentType = /* ... existing ... */ | 'megaclaw';

export const AGENT_TYPES: readonly AgentType[] = [
  /* ... existing ... */ 'megaclaw',
];
```

If the new adapter is an interactive coding agent (different threat model from autonomous servers — gateway binding doesn't apply, but approval/permission settings do), add it to `CODING_AGENTS` as well so server-only checks with `excludedAgents: CODING_AGENTS` correctly skip it.

### 2. Create the Adapter

Create `src/adapters/megaclaw.ts`. Read host state through the `fs` provider — never call `node:fs/promises` or `os.homedir()` directly, or snapshot/SSH scans will silently produce host-dependent results:

```typescript
import { join } from 'node:path';
import type { AgentAdapter, DetectOptions } from './adapter.js';
import type { AgentInstallation, GatewayInfo } from '../core/types.js';
import { loadConfig } from '../core/config-loader.js';
import { LocalFSProvider } from '../core/local-fs-provider.js';

export const megaclawAdapter: AgentAdapter = {
  agent: 'megaclaw',
  displayName: 'MegaClaw',

  async detect(options?: DetectOptions): Promise<AgentInstallation[]> {
    const fs = options?.fs ?? new LocalFSProvider();
    const installDir = join(fs.homedir(), '.megaclaw');
    if (!(await fs.exists(installDir))) return [];

    const configFiles = [];
    for (const filename of ['config.json', 'settings.yaml', '.env']) {
      try {
        configFiles.push(await loadConfig(join(installDir, filename), fs));
      } catch {}
    }

    if (configFiles.length === 0) return [];

    const merged: Record<string, unknown> = {};
    for (const c of configFiles) Object.assign(merged, c.data);

    return [{
      agent: 'megaclaw',
      installDir,
      configFiles,
      skillsDir: this.getSkillsDir(installDir),
      gateway: this.getGatewayInfo(merged),
    }];
  },

  getConfigPaths(): string[] {
    // Used by the Go probe to know what files to collect for SSH scans.
    return ['config.json', 'settings.yaml', '.env'];
  },

  getSkillsDir(installDir: string): string | undefined {
    return join(installDir, 'skills');
  },

  getGatewayInfo(config: Record<string, unknown>): GatewayInfo | undefined {
    const gw = config.gateway as Record<string, unknown> | undefined;
    if (!gw) return undefined;
    return {
      host: gw.host as string | undefined,
      port: gw.port as number | undefined,
      authMode: gw.authMode as string | undefined,
      tls: gw.tls as boolean | undefined,
    };
  },

  getCredentialPaths(installDir: string): string[] {
    return [join(installDir, '.env'), join(installDir, 'auth.json')];
  },

  getCLICommand(): string {
    return 'megaclaw';
  },
};
```

For SSH/snapshot support, also implement `getProbeManifest()` — it tells the static Go probe which files, globs, command outputs, and directory listings to collect on a remote target. See `src/adapters/openclaw.ts` for a worked example.

### 3. Register the Adapter

Add it to the `allAdapters` array in `src/adapters/index.ts`. `registerAllAdapters()` (called by `src/cli.ts` at startup, and exported by the library entry) registers every entry:

```typescript
import { megaclawAdapter } from './megaclaw.js';

export const allAdapters: AgentAdapter[] = [
  // ... existing adapters
  megaclawAdapter,
];
```

`src/index.test.ts` asserts the adapter and check totals — update it when you add an adapter or checks.

### 4. Agent-Specific Checks

If the new agent has unique security concerns, create checks with `supportedAgents` set:

```typescript
export const cfg017: CheckModule = {
  id: 'CFG-017',
  name: 'MegaClaw Debug Mode',
  category: 'config',
  severity: 'critical',
  description: 'Check if MegaClaw debug mode is enabled',
  supportedAgents: ['megaclaw'],  // Only runs for MegaClaw

  async run(ctx: ScanContext): Promise<CheckResult> {
    // ... detection logic
  },
};
```

Checks without `supportedAgents` run for all agents automatically.

---

## Adding a New Output Reporter

### 1. Create the Reporter

Create `src/reporting/html.ts`:

```typescript
import type { ScanResult } from '../core/types.js';
import type { Reporter } from './reporter.js';

export class HtmlReporter implements Reporter {
  readonly format = 'html';

  render(result: ScanResult): string {
    const findings = result.agents.flatMap(a =>
      a.results.filter(r => !r.passed)
    );

    return `<!DOCTYPE html>
<html>
<head><title>VASO Report</title></head>
<body>
  <h1>VASO Security Scan</h1>
  <p>Score: ${result.totalScore}/100 (${result.totalGrade})</p>
  <p>Critical: ${result.summary.critical} | Warning: ${result.summary.warning} | Info: ${result.summary.info}</p>
  <table>
    <tr><th>ID</th><th>Name</th><th>Severity</th><th>Message</th></tr>
    ${findings.map(f => `<tr><td>${f.id}</td><td>${f.name}</td><td>${f.severity}</td><td>${f.message}</td></tr>`).join('\n')}
  </table>
</body>
</html>`;
  }
}
```

### 2. Register the Reporter

In `src/reporting/index.ts`:

```typescript
import { HtmlReporter } from './html.js';

const reporters: Record<string, () => Reporter> = {
  terminal: () => new TerminalReporter(),
  json: () => new JsonReporter(),
  sarif: () => new SarifReporter(),
  markdown: () => new MarkdownReporter(),
  html: () => new HtmlReporter(),
  csv: () => new CsvReporter(),
  junit: () => new JunitReporter(),
};
```

You can also register reporters dynamically — this is the path user plugins under `~/.vaso/plugins/` use. A name that is already taken (a built-in format or another plugin's) is refused:

```typescript
import { registerReporter } from './reporting/index.js';

registerReporter('my-format', () => new MyReporter());
```

### 3. Wire the CLI Option

In `src/cli.ts`, `--format` is checked before any work starts (`validateFormatOption()` against `reportFormats()`, which includes plugin-registered formats), so a registered reporter is accepted automatically; add the name to `OutputFormat` for type-safety inside the engine and update the help string:

```typescript
.option('-f, --format <format>',
  'output format (terminal, json, sarif, markdown, html, csv, junit)', 'terminal')
```

---

## Adding a New Check Category

You only need a new category when an existing one doesn't fit. The 19 existing categories cover broad ground; check whether your new check belongs in one of them first.

### 1. Extend CheckCategory

Add to both the union and runtime array in `src/core/types.ts` (mirroring how `AgentType` is extended).

### 2. Create the Category Directory + Index

```bash
mkdir src/checks/<category>
```

```typescript
// src/checks/<category>/index.ts
import type { CheckModule } from '../../core/types.js';
import { example001 } from './example-001-something.js';

export const <category>Checks: CheckModule[] = [example001];
```

### 3. Register in the Master Index

Edit `src/checks/index.ts` and append the new category to the imports and the `registerAllChecks()` body. The full body currently registers 32 arrays — one per `src/checks/*/` directory:

```typescript
import { <category>Checks } from './<category>/index.js';

export function registerAllChecks(): void {
  // ... existing categories
  checkRegistry.registerAll(<category>Checks);
}
```

If the new category has a corresponding adapter (e.g. you're adding agent-specific checks for a new framework), also update that adapter's `getZoneGraph()` so the privilege-gradient diagram knows the new check IDs.

---

## Working with the Analyzers

### AST Analyzer

`src/analyzers/ast-analyzer.ts` parses JavaScript/TypeScript with `@babel/parser` and walks the AST with `@babel/traverse`.

```typescript
import { analyzeCode } from '../analyzers/ast-analyzer.js';

const flows = analyzeCode(sourceCode, filePath);
```

Returns an array of `DataFlowResult` objects:

```typescript
interface DataFlowResult {
  type: 'source-to-sink' | 'eval-exec' | 'suspicious-network' | 'fs-access';
  source?: string;
  sink?: string;
  line: number;
  snippet: string;
  description: string;
}
```

Tracked sources: `readFile`, `readFileSync`, `createReadStream`, `readdir`, `readdirSync`, and `process.env` accesses.

Tracked sinks: `fetch`, `request`, `get`, `post`, `put`, `patch`, `send`, `write`, `emit`. Tracked network modules: `http`, `https`, `net`, `dgram`, `axios`, `got`, `node-fetch`, `undici`, `request`.

Sensitive paths flagged via `fs-access`: `~/.ssh/`, `~/.aws/`, `~/.gnupg/`, `~/.kube/`, `.env`, `/etc/passwd|shadow|hosts`, `~/.docker/config`, plus anything matching `credentials`/`secret`.

### Pattern Engine

`src/analyzers/pattern-engine.ts` runs regex rules against source code line-by-line. Comment lines (`//`, `*`) are skipped so JSDoc and inline notes don't trigger findings — but markdown `#` headings are intentionally not skipped (SKL-007 and CC-011 scan `.md` content where `#` carries meaning).

```typescript
import { scanWithPatterns, SECURITY_PATTERNS } from '../analyzers/pattern-engine.js';

// All built-in patterns
const allMatches = scanWithPatterns(code);

// Filter to a subset of categories
const reverseShellRules = SECURITY_PATTERNS.filter(r => r.category === 'reverse-shell');
const matches = scanWithPatterns(code, reverseShellRules);
```

Built-in categories: `reverse-shell`, `curl-pipe`, `credential-harvest`, `exfiltration`, `prompt-injection`, `crypto-wallet`, `obfuscation`, `code-exec`.

Returns an array of `PatternMatch`:

```typescript
interface PatternMatch {
  pattern: string;    // Rule identifier (e.g. "RS-001")
  category: string;   // Category name
  severity: Severity;
  line: number;
  snippet: string;
  description: string;
}
```

To add patterns, append to the `SECURITY_PATTERNS` array in `pattern-engine.ts`:

```typescript
{ id: 'EX-004', category: 'exfiltration', severity: 'critical',
  pattern: /ngrok\.io|serveo\.net/i,
  description: 'Tunneling service domain detected' },
```

### Entropy Analyzer

`src/analyzers/entropy.ts` calculates Shannon entropy to detect obfuscated or packed code.

```typescript
import { shannonEntropy, findHighEntropyBlocks } from '../analyzers/entropy.js';

// Single string
const entropy = shannonEntropy('some string');

// Find high-entropy blocks in source code (threshold: 5.5 bits/char, min length: 40)
const blocks = findHighEntropyBlocks(code);
// Returns: { content: string, entropy: number, line: number }[]
```

---

## IOC Database

The bundled IOC database is in `src/ioc/database.ts`. To add new indicators:

```typescript
// In database.ts, add to the appropriate array, with a source reference:
const C2_IPS = [
  // ... existing IPs
  '<ip>',  // <campaign> — <primary source URL>
];

const MALICIOUS_DOMAINS = [
  // ... existing domains
  '<domain>',  // <campaign> — <primary source URL>
];
```

Only add verified, sourced indicators. `src/ioc/database.test.ts` rejects placeholder values in both the bundled database and `feeds/feed.json`: well-known test-vector hashes and documentation (RFC 5737), private (RFC 1918), loopback, link-local, and scan-test IPs. Test fixtures should use a real indicator already in the database (e.g. the ClawHavoc C2 `91.92.242.30`).

The `vaso update` command fetches signed remote IOC and advisory feeds. Feeds are verified with a pinned Ed25519 public key (`src/ioc/public-key.ts`), and rejected on version rollback to prevent downgrade attacks. The bundled `database.ts` indicators remain the offline baseline — VASO is always usable without ever reaching the network. See `src/ioc/updater.ts` and `src/advisory/updater.ts` for the fetch + verify flow.

### Typosquatting Detection

Add trusted skill names to `TRUSTED_SKILL_NAMES` in `src/ioc/database.ts` (MCP packages go in `TRUSTED_MCP_PACKAGES`):

```typescript
const TRUSTED_SKILL_NAMES = [
  // ... existing names
  'new-trusted-skill',
];
```

`src/ioc/typosquat.ts` compares names case-insensitively with `-`/`_` removed, using optimal string alignment distance (Levenshtein where an adjacent transposition counts as one edit). The allowed distance scales with the trusted name's length: names of 4 characters or fewer must match exactly, 5–9 characters allow 1 edit, 10+ allow 2. An exact match with any trusted name is never flagged.

---

## Scoring System

Defined in `src/core/scoring.ts`:

- Base score: 100
- Each failed **critical** check: -12 points
- Each failed **warning** check: -5 points
- **Info** findings: no score impact
- Score is clamped to 0-100

Grades: A (90+), B (80+), C (70+), D (60+), F (<60).

When multiple agents are scanned, the headline `totalScore`/`totalGrade` is worst-case — the lowest per-agent score — so one weak agent can't be averaged away. The mean is still reported as `ScanResult.fleetAverage`.

---

## Config Loader

`src/core/config-loader.ts` auto-detects file format by extension and reads through an `FSProvider` so snapshot scans work:

| Extension | Parser |
|-----------|--------|
| `.json` | `JSON.parse` |
| `.yaml`, `.yml` | `yaml` npm package |
| `.toml` | `smol-toml` |
| `.env` | Custom parser (handles quotes, comments) |
| (unknown) | Tries JSON → YAML → TOML in order, falls back to `{}` |

Plist files (`.plist`, used by Claude Desktop and ChatGPT Desktop adapters) are read through the `plist` npm package directly in the adapter, not via `loadConfig` — `plutil -convert json` refuses to render NSDate/NSData-bearing plists, so we parse the binary form ourselves.

`loadConfig(filePath, fs?)` returns a `ParsedConfig` with both the raw string content and the parsed `data` object. Checks can use either for detection (structured lookup via `data`, or regex via `raw`). Pass `ctx.fs` so the read flows through whichever FSProvider the engine is using.

---

## Build and Test

```bash
npm run build          # tsup: src/cli.ts → dist/cli.js, src/index.ts → dist/index.js + .d.ts
npm test               # vitest: run all tests
npx vitest run <path>  # Run a single test file
npm run lint           # tsc --noEmit (type checking only)
npm run dev            # tsup --watch (rebuild on change)
```

The build produces `dist/cli.js` (~1.2 MB, plus a `.map`) with all dependencies bundled except Node.js built-ins, and the library bundle `dist/index.js` + `dist/index.d.ts`.

For SSH/snapshot scanning, the static Go probe under `probe/` is built separately:

```bash
cd probe && make all    # cross-compiles into probe/dist/
```

A binary in `probe/dist/` takes precedence; otherwise VASO downloads the matching release asset and verifies it against `probe/checksums.json`. For `--host` scans the probe is push-deployed, runs once, and is removed. For air-gapped hosts or platforms without SSH access, the probe can be run manually on the target and the resulting snapshot scanned with `vaso scan --snapshot` — see [`network-scanning-guide.md`](network-scanning-guide.md).

---

## Conventions

- **Check IDs** are uppercase: `CFG-001`, `SKL-003`, `IOC-005`, `MCP-001`, `LY-018`, `GHC-008`
- **File names** are lowercase with the ID + short slug: `cfg-001-gateway-binding.ts`, `mcp-019-toxic-tool-flow.ts`
- **Exports** use camelCase matching the ID: `cfg001`, `skl003`, `mcp019`, `ly018`
- **Category indexes** export a `<category>Checks` array: `configChecks`, `skillChecks`, `mcpChecks`, `lyrieChecks`
- **Tests** go in `.test.ts` files alongside the source or in a shared `<category>-checks.test.ts`
- Checks without `supportedAgents` apply to all agents
- Use `excludedAgents: CODING_AGENTS` for server-only concerns (gateway binding, LaunchAgents, rate limiting) so interactive coding agents don't false-positive
- Checks without `supportedPlatforms` apply to all platforms
- **Read host state through `ctx.fs`** — never `os.homedir()`, `process.env`, or `node:fs/promises`. Snapshot scans depend on this; the validation-report sweep (v0.4.1) systematically removed the violations.
- All analysis is read-only; only `fix()` methods modify the filesystem (and they go through `ctx.fs` too)
- `fix()` must return a `FixResult` indicating whether the fix was applied
- AgentAdapter `detect()` returns `Promise<AgentInstallation[]>` (plural) — a host can have multiple installs of the same agent
- New adapters should implement `getProbeManifest()` so they work over SSH out of the box
- Zone graphs (`getZoneGraph()`) are validated against the live check registry at startup — a typo in a check ID fails CI
