# Changelog

All notable changes to VASO (VULNEX Agent Security Observer) will be documented in this file.

This project adheres to [Semantic Versioning](https://semver.org/).

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
- 124 tests across 14 test files
- Coverage: core engine, scoring, config loader, check registry, all 15 config checks, AST analyzer, pattern engine, entropy analyzer, IOC database, typosquatting, SARIF output, markdown output, baseline diffing, detect command

[0.1.0]: https://github.com/vulnex/vaso/releases/tag/v0.1.0
