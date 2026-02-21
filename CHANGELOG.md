# Changelog

All notable changes to VASO (VULNEX Agent Security Observer) will be documented in this file.

This project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

#### IOC Auto-Updater with Ed25519-Signed Threat Feeds
- **Pull-based feed system** (`src/ioc/updater.ts`): fetches remote IOC feed JSON + detached `.sig` from configurable URL, verifies Ed25519 signature via `node:crypto`, persists to `~/.vaso/ioc/`, merges additively with bundled data — zero new npm dependencies
- **Ed25519 signature verification**: mandatory on every fetch and every cache load (catches local tampering); 64-byte signature length enforcement; key pinning with no TOFU — rotation requires new VASO release
- **Feed version monotonicity**: rejects downgrades (remote version must exceed cached version); `--force` flag overrides staleness and version checks
- **Additive merge**: remote feed extends bundled data (union with deduplication for strings via Set, RegExp by source+flags, BinaryPattern by name+type); bundled indicators are always present regardless of feed state
- **Staleness detection**: configurable threshold (default 7 days) based on `~/.vaso/ioc/metadata.json` timestamps; stale/missing feed triggers yellow warning on all non-update commands
- **`initIOCDatabase()`**: async startup initializer loads cached feed and merges with bundled data; idempotent; `getIOCDatabase()` falls back to bundled-only if never called
- **`vaso update` command**: real fetch-verify-persist-reload flow replacing the previous stub; prints per-field new indicator counts and merged database totals; accepts `--url <url>` (custom feed) and `--force` options
- **CLI preAction hook**: now async; calls `initIOCDatabase()` on every command; shows staleness warning for non-update commands
- **Feed type definitions** (`src/ioc/feed-types.ts`): `IOCFeed`, `IOCFeedData`, `SerializedRegExp`, `SerializedBinaryPattern`, `IOCFeedMetadata`, `UpdateResult` interfaces
- **Public key module** (`src/ioc/public-key.ts`): bundled Ed25519 public key PEM, default feed URL, staleness threshold constants
- **Maintainer scripts**: `scripts/generate-feed-keypair.mjs` (generates Ed25519 keypair), `scripts/sign-feed.mjs` (produces detached base64 `.sig` file)
- 33 new tests in `src/ioc/updater.test.ts`: signature verification (valid, tampered, wrong key, malformed, wrong length), deserialization (RegExp, BinaryPattern, flags, empty), merge (all 8 fields, dedup, bundled preservation), staleness (missing, fresh, old, custom threshold, malformed), cached feed (missing, valid, tampered+deleted), fetch cycle (success, network error, bad sig, version downgrade, staleness skip, force bypass), init integration (bundled fallback, idempotent, reset)
- `feed-signing-key.pem` added to `.gitignore`
- Test suite now at 374 tests across 35 test files

#### Missing Design-Spec Checks (11 new checks, 1 new category)
- **SKL-011** (Dependency Audit): checks skill `package.json` deps against known malicious packages (`event-stream`, `flatmap-stream`, etc.) and malicious publishers; warns on missing lockfile (warning)
- **SKL-012** (Code Complexity): cyclomatic complexity per function via Babel AST traversal; flags functions exceeding threshold of 15 decision points (info)
- **IOC-007** (Binary Pattern Match): YARA-like byte/regex patterns on skill files — detects embedded ELF, Mach-O 64/32-bit, PE/DOS binaries, NUL-padding shellcode markers, and packed JS eval wrappers (critical)
- **IOC-008** (VirusTotal Cross-Reference): SHA-256 hashes skill files and checks against VirusTotal API; opt-in via `VIRUSTOTAL_API_KEY` env var, passes gracefully when no key is set (critical)
- **NET-005** (Active Connection Monitoring): parses `netstat`/`ss` output for ESTABLISHED connections and cross-references IPs against C2 database; darwin/linux only (critical)
- **RUN-005** (Process Ancestry Analysis): walks PPID chain (max 5 levels) for agent processes, flags suspicious parents like `curl`, `wget`, `nc`, `python`, `bash -c`; darwin/linux only (warning)
- **POL-001** (Exec Approval Required): verifies tool execution requires user approval — detects `auto_approve: true`, `execApproval: false`, and `AGENT_AUTO_APPROVE_TOOLS` env var (warning)
- **POL-002** (Log Redaction): verifies logging has secret redaction configured when logging is enabled (warning)
- **POL-003** (Session Credential Permissions): `stat()` on session/token/auth/credential files for 0600 permissions; darwin/linux only (warning)
- **POL-004** (Sandbox Policy Enforcement): when sandbox is enabled, verifies it has ≥2 substantive constraints (exec, filesystem, network restrictions) (warning)
- **POL-005** (Plaintext Credential Files): scans `.npmrc`, `.netrc`, `.pgpass`, `.my.cnf`, `.s3cfg`, `credentials`, `secrets.txt`, `.boto`, `.pypirc`, `.authinfo` against `API_KEY_PATTERNS` (critical)
- **`binaryPatterns`** field added to `IOCDatabase` interface with 6 seed patterns (ELF, Mach-O 64-bit, Mach-O 32-bit, PE/DOS, NUL shellcode, packed JS)
- **`policy`** check category added — `src/checks/policy/` with 5 checks and barrel index
- 34 new tests: `skill-checks.test.ts` (7), `ioc-checks.test.ts` (6), `network-checks.test.ts` (2), `runtime-checks.test.ts` (3), `policy-checks.test.ts` (16)
- Test suite now at 341 tests across 34 test files
- Total security checks: 98

#### HTML Output Format
- **HTML reporter** (`src/reporting/html.ts`): self-contained, browser-viewable scan report with all CSS inlined — no external dependencies or JavaScript frameworks required
- Color-coded severity badges (critical=#dc2626, warning=#d97706, info=#2563eb), grade-colored score display (A/B=green, C=amber, D/F=red), summary cards row, per-agent findings tables with striped rows, passed checks lists, and evidence file:line references
- Responsive layout using CSS grid — works on mobile (collapses to 2-column cards and single-column passed lists at 600px)
- XSS-safe HTML escaping for all user-controlled content (messages, evidence, config values)
- `--format html` available on `vaso scan` and `vaso mcp scan` commands
- `'html'` added to `OutputFormat` type union
- 11 tests in `src/reporting/html.test.ts`: HTML structure, content rendering, severity labels, agent name display, evidence rendering, HTML escaping, empty agents, fixable indication, metadata, format property
- Test suite now at 307 tests across 29 test files

#### Per-Agent Scanning for OpenClaw Multi-Agent Installations
- **`agentName`** and **`skillsDirs`** fields added to `AgentInstallation` — `agentName` identifies sub-agent definitions (e.g. `"researcher"`, `"coder"`), `skillsDirs` supports multiple skill directories (shared + per-agent)
- **OpenClaw adapter** now discovers `agents/` subdirectories within each installation: for each sub-agent, loads agent-specific configs (`agent.yaml`, `agent.json`, `config.yaml`, `config.json`, `.env`), deep-merges with global config (agent overrides global), and emits a separate `AgentInstallation` with merged configs and combined skill directories
- **`deepMerge()`** utility in `src/core/utils.ts`: recursive object merge where override wins for conflicts, arrays from override replace base arrays
- **Terminal reporter** shows `agent: <name>` in scan headers when sub-agents are present
- **`vaso detect`** shows agent name in output and sub-agent count in summary (e.g. `Found 3 agent(s) (2 sub-agent definitions).`)
- **Markdown reporter** includes `(agent: <name>)` in section headers
- **SARIF reporter** includes `agentName` in result properties
- No changes needed to scan engine, check modules, remediation engine, or config writer — they already operate on `AgentInstallation[]` and `ScanContext`

#### Tests
- `src/core/utils.test.ts`: 9 tests covering `getNestedValue`, `setNestedValue`, and `deepMerge` (shallow merge, deep nested merge, override wins, array replacement, immutability, empty objects)
- `src/adapters/openclaw-agents.test.ts`: 5 tests for per-agent discovery (multi-agent detection with config merging and skillsDirs, global-only fallback, agentName correctness, cliBinary/appBundle inheritance, non-directory entry filtering)
- Test suite now at 296 tests across 28 test files

#### Remediation Engine — `vaso fix` Now Works
- **Config writer utilities** (`src/remediation/config-writer.ts`): `updateEnvFile()`, `updateJsonFile()`, `updateYamlFile()`, `updateTomlFile()`, `chmodFile()`, and `updateConfigValue()` dispatcher — handles all 4 config formats with comment/indentation preservation
- **`setNestedValue()`** in `src/core/utils.ts`: write counterpart to `getNestedValue()`, creates intermediate objects as needed
- **Rollback support** (`src/remediation/rollback.ts`): restores files from `~/.vaso/backups/` by timestamp; `vaso fix --rollback` now functional (previously printed "not implemented yet")
- **42 `fix()` methods** across all fixable checks:

  **IronClaw (12 checks)** — 8 automatable, 4 guidance-only:
  - IC-001: `HTTP_HOST=127.0.0.1`
  - IC-003: `ORCHESTRATOR_HOST=127.0.0.1`
  - IC-004: generates random 32-byte hex `GATEWAY_AUTH_TOKEN`
  - IC-005: `SANDBOX_ENABLED=true`
  - IC-006: `SANDBOX_POLICY=restricted`
  - IC-007: `AGENT_AUTO_APPROVE_TOOLS=false`
  - IC-008: `ALLOW_LOCAL_TOOLS=false`
  - IC-012: `SANDBOX_AUTO_PULL=false`
  - IC-002, IC-009, IC-010, IC-011: return manual action guidance

  **Config (7 checks)** — 6 automatable, 1 file permission:
  - CFG-001: `gateway.host=127.0.0.1`
  - CFG-005: adds `safeBins` allowlist with 8 safe defaults
  - CFG-008: `sandbox=true`
  - CFG-010: adds `rateLimit` (60 req/min)
  - CFG-012: `auth.bypass=false`
  - CFG-013: `dm.policy=restricted`
  - CFG-003: `chmod 600` on all overly-permissive config files

  **Nanobot (10 checks)** — 5 automatable, 5 guidance-only:
  - NB-003: `restrictToWorkspace=true`
  - NB-004: adds 13-entry ExecTool `denyList` (rm, curl, wget, etc.)
  - NB-005: adds SSRF-blocking `blockedHosts` (localhost, private IPs, metadata endpoint)
  - NB-009: `sessions.encryption=true`
  - NB-011: adds `rateLimit` (30/min, 500/hr)
  - NB-001, NB-002, NB-008, NB-010, NB-012: return manual action guidance

  **ZeroClaw (13 checks)** — 7 automatable, 1 file permission, 5 guidance-only:
  - ZC-001: `secrets.encrypt=true`
  - ZC-003: `security.allow_public_bind=false`
  - ZC-004: `require_pairing=true`
  - ZC-005: `autonomy.level=supervised`
  - ZC-006: `workspace_only=true`
  - ZC-008: `skills.open_install=false`
  - ZC-014: `runtime.sandbox=firejail`
  - ZC-013: `chmod 600` on `.secret_key`
  - ZC-002, ZC-007, ZC-009, ZC-011, ZC-012: return manual action guidance

#### Tests
- `src/remediation/config-writer.test.ts`: 16 tests covering all 5 writer functions, format preservation, and dispatcher routing
- `src/remediation/remediation.test.ts`: 17 integration tests — end-to-end fix→verify cycles for representative checks from each agent category, guidance-only checks, file permissions, and rollback
- Test suite now at 282 tests across 26 test files

### Changed

- **Adapter `detect()` signature**: `AgentAdapter.detect()` now returns `Promise<AgentInstallation[]>` instead of `Promise<AgentInstallation | null>`, enabling adapters to report multiple installations (e.g. different users or profiles)
- **`AdapterRegistry.detectAll()`** accepts optional `DetectOptions` and flatMaps adapter results
- **NanoClaw/PicoClaw adapters**: updated to new `detect()` signature (return `[]`/`[installation]`)
- **Shared utilities extracted**: `getNestedValue()` (from 13 files), `getSkillFiles()` (from 10 files), and `pathExists()` (from 3 adapters) consolidated into `src/core/utils.ts` to eliminate duplication
- **CFG-001 (Gateway Binding)**: now detects IPv6 wildcard binds (`[::]`, `::`) alongside `0.0.0.0`, and checks `server.host` config path for ZeroClaw TOML support

### Added

#### IronClaw Agent Support
- **IronClaw adapter** (`src/adapters/ironclaw.ts`): detects `~/.ironclaw/` config dir with `.env`, `config.toml`, `settings.json`, `mcp-servers.json`; CLI binary via `~/.cargo/bin/ironclaw` or `which` fallback; gateway extraction from env vars and TOML `[gateway]` section
- **IC-001** (HTTP Webhook Public Bind): detects `HTTP_HOST=0.0.0.0` default on port 8080 (critical)
- **IC-002** (No TLS on Listeners): checks all 3 listeners (gateway/webhook/orchestrator) for TLS cert configuration (critical)
- **IC-003** (Orchestrator Public Bind): detects `ORCHESTRATOR_HOST=0.0.0.0` on gRPC port 50051 (critical)
- **IC-004** (Missing Gateway Auth Token): flags missing/empty `GATEWAY_AUTH_TOKEN` with ephemeral random fallback (warning)
- **IC-005** (Sandbox Disabled): detects `SANDBOX_ENABLED=false` in .env or TOML (critical)
- **IC-006** (Full Access Sandbox Policy): detects `SANDBOX_POLICY=full_access` granting unrestricted system access (critical)
- **IC-007** (Auto-Approve Tools): detects `AGENT_AUTO_APPROVE_TOOLS=true` bypassing all tool approval prompts (critical)
- **IC-008** (Local Tools Bypass): detects `ALLOW_LOCAL_TOOLS=true` allowing tool execution outside sandbox (warning)
- **IC-009** (Secrets Key in .env): detects plaintext `SECRETS_MASTER_KEY` in config files (critical)
- **IC-010** (Telegram Without Owner ID): flags Telegram enabled without `TELEGRAM_OWNER_ID` restriction (warning)
- **IC-011** (Broad Sandbox Domains): detects wildcard patterns in `SANDBOX_EXTRA_DOMAINS` (warning)
- **IC-012** (Docker Auto-Pull No Digest): flags `SANDBOX_AUTO_PULL=true` without `@sha256:` digest pinning (warning)

#### Nanobot Agent Support
- **Nanobot adapter** (`src/adapters/nanobot.ts`): detects `~/.nanobot/config.json`; skills at `workspace/skills/`; memory files (MEMORY.md, HEARTBEAT.md, SOUL.md); gateway from root `host`/`port` (default `0.0.0.0:18790`); CLI binary via `which` fallback
- **NB-001** (Empty Channel allowFrom): detects `channels.*.allowFrom: []` with no access control (critical)
- **NB-002** (Plaintext Secrets): scans config.json for plaintext API keys using `API_KEY_PATTERNS` (critical)
- **NB-003** (Workspace Sandboxing Off): detects `restrictToWorkspace: false` (default) (warning)
- **NB-004** (Weak Shell Filtering): flags ExecTool denylist that is missing, empty, or shorter than 5 entries (critical)
- **NB-005** (No SSRF Protection): detects WebFetchTool without `blockedHosts`/`allowedHosts` restrictions (warning)
- **NB-006** (Heartbeat Injection Risk): flags writable HEARTBEAT.md executed every 30min (warning)
- **NB-007** (Memory Prompt Injection): detects MEMORY.md loaded into system prompt — persistent injection vector (critical)
- **NB-008** (WhatsApp Bridge No Token): flags WhatsApp enabled without `bridge_token` (warning)
- **NB-009** (Unencrypted Sessions): detects session JSONL files stored without encryption (warning)
- **NB-010** (Cron Arbitrary Channels): flags cron jobs targeting wildcard channels/recipients (warning)
- **NB-011** (No Rate Limiting): detects missing rate limiting on channels (warning)
- **NB-012** (ClawHub via npx): flags skill install via `npx` — supply chain risk (warning)

#### ZeroClaw Agent Support
- **ZeroClaw adapter** (`src/adapters/zeroclaw.ts`): detects `~/.zeroclaw/` with `config.toml`, `auth-profiles.json`; skills at `workspace/skills/`; CLI binary via `~/.cargo/bin/zeroclaw` or `which`; gateway from TOML `[server]` or `[gateway]` section (default port 3000); credential paths include `.secret_key`
- **ZC-001** (Plaintext API Keys): detects `secrets.encrypt=false` with API keys in config (critical)
- **ZC-002** (Legacy XOR Encryption): detects `enc:` prefix values — trivially reversible XOR cipher (critical)
- **ZC-003** (Public Bind No Tunnel): detects `allow_public_bind=true` + `tunnel.provider=none` (critical)
- **ZC-004** (Pairing Disabled): detects `require_pairing=false` allowing unauthenticated device connections (warning)
- **ZC-005** (Full Autonomy Mode): detects `autonomy.level=full` bypassing all approval gates (critical)
- **ZC-006** (Unrestricted Filesystem): detects `workspace_only=false` allowing access beyond workspace (warning)
- **ZC-007** (Wildcard Channel Users): detects `"*"` in `allowed_users` for any channel (critical)
- **ZC-008** (Open Skills Enabled): flags `skills.open_install=true` — supply chain risk via public repos (warning)
- **ZC-009** (Missing WhatsApp App Secret): detects webhooks accepted without HMAC signature verification (warning)
- **ZC-010** (Composio Integration): flags 1000+ OAuth apps attack surface when enabled (info)
- **ZC-011** (Browser No Domain Allowlist): detects browser tool without `allowed_domains` (warning)
- **ZC-012** (HTTP Tool No Domain Filter): detects HTTP request tool without domain restrictions (warning)
- **ZC-013** (.secret_key Permissions): checks file mode is 0600; linux/darwin only (critical)
- **ZC-014** (No OS-Level Sandbox): detects `runtime.kind=native` without Firejail/Bubblewrap/Landlock (warning)

#### Infrastructure
- **TOML config parsing**: added `smol-toml` dependency; `.toml` format detection, parsing, and fallback in `config-loader.ts`; `'toml'` added to `ParsedConfig.format` union
- **Type extensions**: `AgentType` union extended with `'ironclaw' | 'nanobot' | 'zeroclaw'`; `CheckCategory` union extended with `'ironclaw' | 'nanobot' | 'zeroclaw'`
- **Telegram Bot token pattern** added to `API_KEY_PATTERNS` in `src/core/patterns.ts`
- **`src/core/utils.ts`**: shared `getNestedValue()`, `getSkillFiles()`, `pathExists()` — imported by 23+ check and adapter files

#### Tests & Fixtures
- 3 adapter unit tests: `ironclaw.test.ts` (9 tests), `nanobot.test.ts` (8 tests), `zeroclaw.test.ts` (8 tests)
- 3 check unit tests: `ironclaw-checks.test.ts`, `nanobot-checks.test.ts`, `zeroclaw-checks.test.ts`
- TOML parsing test added to `config-loader.test.ts`
- Test fixtures for all 3 agents: insecure configs (triggering all agent-specific checks), secure configs, malicious and safe skill directories
- 3 Dockerfiles: `ironclaw.Dockerfile`, `nanobot.Dockerfile`, `zeroclaw.Dockerfile`
- 3 integration test suites: `ironclaw.integration.test.ts`, `nanobot.integration.test.ts`, `zeroclaw.integration.test.ts`
- Test suite now at 249 tests across 24 test files
- Total security checks: 83 (45 existing + 12 IC + 12 NB + 14 ZC) — all 45 existing checks automatically apply to new agents (no `supportedAgents` filter)

### Added

#### Multi-user Scanning
- `--all-users` flag on `vaso scan` and `vaso detect` — when running as root/sudo, enumerates all user home directories (`/Users/*` on macOS, `/home/*` + `/root` on Linux) to find agent installations across all accounts
- `DetectOptions` interface in `src/adapters/adapter.ts` with `allUsers` flag, threaded from CLI through engine to adapters
- `getUserHomeDirs()` helper (exported from OpenClaw adapter for testability) — excludes `Shared`, `Guest`, `.localized`

#### OpenClaw Detection Enhancements
- **`OPENCLAW_PROFILE` support**: reads the `OPENCLAW_PROFILE` env var and searches `~/.openclaw-{PROFILE}` directories alongside the default `~/.openclaw`; stored in `AgentInstallation.profile`
- **CLI binary detection**: checks system paths (`/usr/local/bin`, `/opt/homebrew/bin`, `/usr/bin`), user-relative paths (`~/.volta/bin`, `~/.local/bin`, `~/.nvm/current/bin`, `~/bin`), and `which openclaw` fallback; stored in `AgentInstallation.cliBinary`
- **macOS `.app` bundle detection**: checks `/Applications/OpenClaw.app`; stored in `AgentInstallation.appBundle`
- **Minimal installation reporting**: returns an installation entry when only a CLI binary or `.app` bundle is found (no config files), enabling `vaso detect` to report partially-installed agents

#### Types
- `AgentInstallation`: added `profile`, `user`, `appBundle`, `cliBinary` fields
- `ScanOptions`: added `allUsers` field

#### CLI & Reporting
- `vaso detect` output now shows CLI binary path, app bundle path, user, and profile when present
- Terminal scan report shows `(user: X, profile: Y)` in agent headers when multi-user or profile data is available

#### Tests
- 12 new unit tests in `src/adapters/openclaw.test.ts`: default detection, profile-aware detection, CLI binary discovery (system paths, `which` fallback), `.app` bundle detection, minimal installation, `OPENCLAW_HOME` support, `getUserHomeDirs()` behavior
- Updated mock adapter in `src/core/engine.test.ts` to match new `detect()` signature
- Test suite now at 272 tests (170 unit + 102 integration) across 24 test files

### Fixed

- **TypeScript type error in `headerParts`**: `detect.ts` and `terminal.ts` inferred `headerParts` as `AgentType[]` from `[inst.agent]`, causing template literal strings (`user: …`, `profile: …`) to fail type-checking; added explicit `string[]` annotation to both
- **testcontainers API compatibility**: `builtImage.imageName` returns an object in testcontainers v11, not a string — use `.string` property when constructing `GenericContainer`
- **SKL-002 (Obfuscated Code)**: Entropy-only detection missed hex escape sequences (3.16 bits/char) and base64 strings (5.13 bits/char) below the 5.5 threshold; added pattern-based detection for hex escape chains, long base64 strings, `String.fromCharCode`, and `atob()`
- **RS-005 regex false positive**: Pattern `/\bSocket\b.*\bsubprocess|exec|spawn\b/i` was parsed as three ungrouped alternations, causing `exec` to match "execution" in comments; fixed to `/\bSocket\b.*\b(?:subprocess|exec|spawn)\b/i`
- **PicoClaw adapter**: `getGatewayInfo()` returned `undefined` unconditionally and `detect()` never populated `gateway` on the installation; implemented gateway extraction matching the OpenClaw adapter pattern
- **PicoClaw secure fixture**: Calculator skill used `Function()` (flagged as critical by SKL-003); replaced with safe token-based arithmetic; added `workspace` and `safeBins` config keys to pass CFG-005/CFG-006

### Added

#### MCP Server Security Scanning
- **MCP discovery engine** (`src/mcp/discovery.ts`): scans all known config locations for Claude Desktop (macOS/Linux/Windows), Claude Code (`~/.claude/mcp.json`, `.mcp.json`), Cursor, Windsurf, and VS Code; parses `mcpServers` blocks with stdio/SSE/streamable-HTTP transport inference
- **MCP source resolver** (`src/mcp/source-resolver.ts`): infers package names from `npx`/`uvx`/`node` commands, resolves local source paths for AST analysis
- **`vaso mcp scan`** command: standalone MCP security scan with `--format`, `--output`, and `--path` options
- **`vaso mcp list`** command: inventory all discovered MCP server configurations
- **MCP-001** (Config Discovery): inventories all configured MCP servers across all agent configs (info)
- **MCP-002** (Transport Security): detects SSE/HTTP on 0.0.0.0, missing TLS, `--no-tls` flags (critical)
- **MCP-003** (Credential Exposure): detects plaintext API keys and high-entropy secrets in env blocks; reuses shared `API_KEY_PATTERNS` and Shannon entropy analysis (critical)
- **MCP-004** (Overprivileged Tools): detects exec/shell/write capabilities in server source via AST analysis (critical)
- **MCP-005** (Tool Input Injection): detects unsanitized LLM/user input flowing to exec, spawn, eval, SQL, and file write sinks (critical)
- **MCP-006** (Data Exfiltration Risk): detects source-to-sink data flow and suspicious network calls in server source via AST (critical)
- **MCP-007** (Prompt Injection via Tool Results): detects raw external HTTP/file content returned unsanitized in tool results; accounts for sanitization presence (warning)
- **MCP-008** (Server Provenance): checks package names against IOC database for typosquatting (Levenshtein distance), malicious publishers, and malicious domain/name patterns (warning/critical)
- **MCP-009** (Permission Scope): detects disproportionate resource access — admin naming, world-writable permissions, root filesystem globbing, Docker privileged mode (warning)
- **MCP-010** (Rug Pull Risk): detects unpinned `npx`/`uvx` versions and auto-install flags that enable supply chain attacks (warning)
- Added `'mcp'` to `AgentType` and `CheckCategory` type unions
- Added `mcpConfigs` and `mcpServerSources` fields to `ScanContext`
- Added `scanMCP()` method to `ScanEngine` for standalone MCP scanning
- Added `trustedMCPPackages` (16 known packages) to IOC database for typosquatting detection
- Extracted shared `API_KEY_PATTERNS` to `src/core/patterns.ts` for reuse across CFG-002 and MCP-003
- 34 new tests: 6 for MCP discovery, 20 for MCP checks (insecure + secure cases for each), 8 for MCP command (`runMCPScan`/`runMCPList`)
- Test fixtures: insecure/secure Claude Desktop configs, vulnerable/safe MCP server source files

#### MCP Integration Testing
- **MCP Dockerfile** (`testing/docker/agents/mcp.Dockerfile`): copies MCP config and vulnerable server source for Docker-based end-to-end tests
- **MCP integration test** (`testing/integration/mcp.integration.test.ts`): insecure scenario asserts all 10 MCP checks (MCP-001 through MCP-010) with correct severities, low score, and failing grade; secure scenario asserts MCP-002, MCP-003, MCP-010 pass with high score and passing grade
- **`mcp-insecure` and `mcp-secure`** services added to `testing/docker-compose.yml`
- **`command` option** added to `VasoScanOptions` in `testing/integration/helpers.ts` to support custom CLI subcommands (e.g., `['mcp', 'scan', '--path', '/mcp/config.json']`); backward-compatible — defaults to `['scan']`
- **MCP command unit test** (`src/commands/mcp.test.ts`): 8 tests covering `runMCPScan` (path discovery, platform discovery, no servers, critical exit code) and `runMCPList` (JSON output, terminal output, no servers, platform discovery)

#### Docker Integration Testing Infrastructure
- **testcontainers** integration for programmatic Docker-based integration tests driven by vitest
- Multi-stage base Dockerfile (`testing/docker/base.Dockerfile`) — builds VASO in `node:20-slim`, copies only runtime artifacts to final image
- Agent-specific Dockerfiles for OpenClaw, NanoClaw, PicoClaw, and multi-agent scenarios with `ARG SCENARIO` for insecure/secure switching
- Fixture files for all three agents:
  - **OpenClaw insecure**: triggers CFG-001, CFG-002, CFG-004, CFG-007, CFG-008, CFG-009, CFG-010, CFG-012, CFG-013, CFG-014, CFG-015, SKL-001, SKL-002, SKL-003, SKL-005, SKL-007, IOC-001, IOC-002, IOC-005
  - **NanoClaw insecure**: triggers CFG-001, CFG-008, CFG-012, CFG-013, CFG-014, SKL-003, IOC-001
  - **PicoClaw insecure**: triggers CFG-001, CFG-002, CFG-008, CFG-009, CFG-012, IOC-002
  - Secure variants for all agents with hardened configs and benign skills
- Test helpers (`testing/integration/helpers.ts`): `buildBaseImage()`, `runVasoScan()`, `findCheck()`, `getAgentResult()`, `expectCheckFailed()`, `expectCheckPassed()`
- 6 integration test suites: `openclaw.integration.test.ts`, `nanoclaw.integration.test.ts`, `picoclaw.integration.test.ts`, `multi-agent.integration.test.ts`, `scoring.integration.test.ts`, `mcp.integration.test.ts`
- Separate vitest config (`testing/vitest.config.integration.ts`) with 120s test timeout, 180s hook timeout
- Docker Compose file (`testing/docker-compose.yml`) with 11 services for manual testing
- GitHub Actions CI workflow (`.github/workflows/integration-tests.yml`) — runs integration tests after unit tests pass
- npm scripts: `test:integration`, `test:all`, `docker:build-base`
- `.dockerignore` for optimized Docker build context

## [0.1.0] - 2026-02-20

Initial release of VASO with full scan engine, 39 security checks, 3 agent adapters, and 5 output formats.

### Added

#### Core Engine
- Scan engine with concurrent check execution via `Promise.allSettled`
- Auto-detection of installed AI agent frameworks
- Scoring system: 100-point scale with letter grades (A-F), -12 per critical, -5 per warning
- Check registry with filtering by category, agent, and platform
- Config loader supporting JSON, YAML, and `.env` formats
- Differential scanning with baseline save/load/diff (`--save-baseline`, `--diff`)

#### CLI
- `vaso detect` command to enumerate installed AI agents without running security checks; supports `--agent`, `--format` (terminal/json), and `--verbose` options
- `vaso scan` command with auto-detect, `--agent`, `--format`, `--output` options
- `vaso fix` command with `--dry-run` and `--yes` modes
- `vaso update` command to reload IOC database
- Exit code 1 when critical findings are detected

#### Agent Adapters
- **OpenClaw** adapter: detects `$OPENCLAW_HOME`, `~/.openclaw`, `~/.clawdbot`, `~/.moltbot`, `/etc/openclaw`; parses `openclaw.json`, `config.yaml`, `gateway.yaml`, `.env`
- **NanoClaw** adapter: detects `~/.nanoclaw.env`, `~/.config/nanoclaw/`
- **PicoClaw** adapter: detects `~/.picoclaw/config.json`, `~/.picoclaw/auth.json`

#### Configuration Checks (15)
- **CFG-001**: Gateway binding to 0.0.0.0 (critical)
- **CFG-002**: API key exposure — 9 patterns including `sk-`, `AKIA`, `ghp_`, `gho_`, `glpat-`, `xoxb-`, `xoxp-`, private keys (critical)
- **CFG-003**: Overly permissive file permissions on config files (warning)
- **CFG-004**: TLS/SSL not configured (warning)
- **CFG-005**: Missing shell command allowlist (`safeBins`) (warning)
- **CFG-006**: No workspace directory restriction (warning)
- **CFG-007**: Webhook endpoints without authentication (warning)
- **CFG-008**: Sandbox disabled (critical)
- **CFG-009**: Default or weak credentials in auth config (critical)
- **CFG-010**: No rate limiting configured (warning)
- **CFG-011**: Node.js CVE-2026-21636 version check (warning)
- **CFG-012**: Authentication bypass enabled (critical)
- **CFG-013**: DM policy set to open (warning)
- **CFG-014**: Permissive tool policy (warning)
- **CFG-015**: mDNS full broadcast enabled (info)

#### Skill Code Analysis Checks (10)
- **SKL-001**: Data exfiltration — AST-based source-to-sink data flow tracing (critical)
- **SKL-002**: Obfuscated code — Shannon entropy analysis, threshold >5.5 bits/char (warning)
- **SKL-003**: Eval/exec usage — detects `eval()`, `new Function()`, `child_process.exec()` (critical)
- **SKL-004**: Curl-pipe execution — `curl|sh`, `wget|bash` patterns (critical)
- **SKL-005**: Reverse shell patterns — 7 detection patterns ported from B@dskills threat model (critical)
- **SKL-006**: Credential harvesting — `.ssh`, `.aws`, `.env` file access via AST + pattern matching (critical)
- **SKL-007**: Prompt injection in SKILL.md — instruction override and delimiter escape patterns (warning)
- **SKL-008**: Suspicious network calls — non-localhost, non-HTTPS connections via AST (warning)
- **SKL-009**: Crypto wallet targeting — wallet address patterns and crypto API usage (warning)
- **SKL-010**: Unauthorized filesystem access — file operations outside workspace via AST (warning)

#### IOC Checks (6)
- **IOC-001**: C2 IP detection — 5 known ClawHavoc campaign IPs (critical)
- **IOC-002**: Malicious domain detection — 9 known payload hosting and exfil domains (critical)
- **IOC-003**: File hash matching — SHA-256 comparison against 4 known AMOS stealer variants (critical)
- **IOC-004**: Malicious publisher detection — 9 blacklisted publishers from ClawHavoc/Bloom campaigns (critical)
- **IOC-005**: Typosquatting detection — Levenshtein distance <= 2 against 20 trusted skill names (warning)
- **IOC-006**: Malicious skill name patterns — 10 regex patterns for known malicious naming conventions (warning)

#### Network Checks (4)
- **NET-001**: Gateway internet exposure — 0.0.0.0 or :: binding detection (critical)
- **NET-002**: WebSocket origin validation — CVE-2026-25253 check (critical)
- **NET-003**: Reverse proxy bypass — `trustProxy` without IP restriction (warning)
- **NET-004**: Port scan for agent services — checks ports 18789, 18790, 3000, 8080, 8443 (info)

#### Runtime Checks (4)
- **RUN-001**: Unauthorized LaunchAgents (macOS) / systemd services (Linux) (warning)
- **RUN-002**: Suspicious cron entries referencing agent paths (warning)
- **RUN-003**: VS Code extension trojans — known malicious extension ID detection (critical)
- **RUN-004**: Docker socket permission check (warning)

#### Analyzers
- AST analyzer using `@babel/parser` + `@babel/traverse` with scope-aware variable tracking and source-to-sink data flow tracing
- Pattern engine with 40+ regex rules across 8 categories: reverse-shell, curl-pipe, credential-harvest, exfiltration, prompt-injection, crypto-wallet, obfuscation, code-exec
- Shannon entropy analyzer for detecting obfuscated/packed code blocks

#### IOC Database
- Bundled threat intelligence: 5 C2 IPs, 9 malicious domains, 4 file hashes, 9 malicious publishers, 10 malicious name patterns, 20 trusted skill names
- Reloadable via `vaso update`

#### Remediation Engine
- Automatic backup to `~/.vaso/backups/{timestamp}/` before modifications
- Dry-run mode for previewing fixes
- Auto-fix support for: gateway rebinding, file permissions, shell allowlist, sandbox enable, auth bypass disable, rate limiting, DM policy

#### Output Formats
- **Terminal**: Styled output with chalk, color-coded by severity
- **JSON**: Structured output with per-agent scores and check results
- **SARIF**: v2.1.0 for GitHub Code Scanning and GitLab SAST integration
- **Markdown**: Tables and sections for PR comments and documentation

#### CI/CD
- GitHub Actions workflow (`.github/workflows/vaso-scan.yml`) with SARIF upload and artifact storage
- `bin/vaso-quick.sh`: Zero-dependency Bash script for 5 critical checks without Node.js

#### Test Suite
- 158 tests across 17 test files
- Coverage: core engine, scoring, config loader, check registry, all 15 config checks, 10 MCP checks, MCP discovery, MCP command, AST analyzer, pattern engine, entropy analyzer, IOC database, typosquatting, SARIF output, markdown output, baseline diffing, detect command

[0.1.0]: https://github.com/vulnex/vaso/releases/tag/v0.1.0
