# Changelog

All notable changes to VASO (VULNEX Agent Security Observer) will be documented in this file.

This project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixed

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
