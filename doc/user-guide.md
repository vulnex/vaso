# VASO User Guide

VASO (VULNEX Agent Security Observer) is a security scanner for AI agent deployments. It detects misconfigurations, malicious skills, known threats, and runtime vulnerabilities across OpenClaw, NanoClaw, PicoClaw installations, and MCP (Model Context Protocol) server configurations.

## Installation

```bash
npm install -g vaso
```

Requirements: Node.js 18 or later.

## Quick Start

Run a full scan with auto-detection:

```bash
vaso scan
```

VASO will search for installed AI agent frameworks, parse their configuration files, analyze skill code, and produce a scored security report.

## Commands

### `vaso scan`

Scans installed agents and reports security findings.

```
vaso scan [options]
```

| Option | Description |
|--------|-------------|
| `-a, --agent <type>` | Scan a specific agent: `openclaw`, `nanoclaw`, or `picoclaw` |
| `-f, --format <format>` | Output format: `terminal` (default), `json`, `sarif`, `markdown` |
| `-o, --output <file>` | Write report to a file instead of stdout |
| `--save-baseline` | Save current results as a baseline for future comparison |
| `--diff` | Compare results against the last saved baseline |
| `--all-users` | Scan all user accounts (requires root/sudo) |
| `--no-color` | Disable colored terminal output |

Examples:

```bash
# Scan only OpenClaw
vaso scan --agent openclaw

# Generate JSON report
vaso scan --format json -o report.json

# Generate SARIF for GitHub Code Scanning
vaso scan --format sarif -o results.sarif

# Generate markdown for PR comments
vaso scan --format markdown -o report.md

# Save a baseline after a clean scan
vaso scan --save-baseline

# Compare against the baseline on subsequent scans
vaso scan --diff
```

### `vaso detect`

Lists installed AI agents without running any security checks. Useful for verifying which agents VASO can see before running a full scan.

```
vaso detect [options]
```

| Option | Description |
|--------|-------------|
| `-a, --agent <type>` | Detect a specific agent only: `openclaw`, `nanoclaw`, or `picoclaw` |
| `-f, --format <format>` | Output format: `terminal` (default) or `json` |
| `--all-users` | Detect across all user accounts (requires root/sudo) |
| `--verbose` | Show the search paths checked for each adapter |

Examples:

```bash
# List all detected agents
vaso detect

# Check if OpenClaw is installed
vaso detect --agent openclaw

# Get machine-readable output
vaso detect --format json

# See where VASO is looking for each agent
vaso detect --verbose
```

Terminal output shows each agent's type, version, install directory, config file count, skills directory, and gateway info. JSON output returns the full `AgentInstallation` array.

### `vaso skill audit`

Audit a local skill directory for security issues before installing it into an agent framework. Runs skill code analysis (SKL-*) and IOC matching (IOC-*) checks against the directory.

```
vaso skill audit <path> [options]
```

| Option | Description |
|--------|-------------|
| `-f, --format <format>` | Output format: `terminal` (default), `json`, `sarif`, `markdown`, `html` |
| `-o, --output <file>` | Write report to a file instead of stdout |
| `--no-color` | Disable colored terminal output |

Examples:

```bash
# Audit a skill before installing
vaso skill audit ./my-downloaded-skill/

# Generate JSON report
vaso skill audit ./skills/web-scraper --format json -o audit.json

# Quick check from a CI pipeline
vaso skill audit ./skills/new-skill && echo "Safe to install"
```

Exit code 1 is returned if any critical findings are detected. If the path does not exist, is not a directory, or contains no code files, VASO reports the issue and exits without scanning.

### `vaso fix`

Automatically remediate fixable findings.

```
vaso fix [options]
```

| Option | Description |
|--------|-------------|
| `-a, --agent <type>` | Fix a specific agent |
| `--dry-run` | Preview fixes without applying them |
| `-y, --yes` | Apply all fixes without prompting |
| `--rollback` | Undo the last fix operation |

When neither `--yes` nor `--dry-run` is set, VASO enters **interactive mode** and prompts for each fixable finding:

```
  CFG-001 [critical]
  Gateway bound to 0.0.0.0
    /home/user/.openclaw/config.json:5
  Fix: Change gateway host to 127.0.0.1
  Apply fix? [y]es / [n]o / [a]ll / [q]uit:
```

| Response | Behavior |
|----------|----------|
| `y` / `yes` | Apply this fix |
| `n` / `no` (default) | Skip this fix |
| `a` / `all` | Apply this fix and all remaining fixes without prompting |
| `q` / `quit` | Skip this fix and stop (return results so far) |

In non-interactive environments (CI pipelines, scripts), VASO requires `--yes` to apply fixes. Without it, fixes are skipped with a warning.

Examples:

```bash
# Interactive mode — prompted for each fix
vaso fix

# Preview what would be fixed
vaso fix --dry-run

# Apply all fixes without prompting (required in CI)
vaso fix --yes

# Fix only OpenClaw issues
vaso fix --agent openclaw
```

Before any modification, VASO backs up affected files to `~/.vaso/backups/<timestamp>/`.

### `vaso update`

Reload the IOC (Indicators of Compromise) threat intelligence database.

```bash
vaso update
```

### `vaso mcp scan`

Scan MCP (Model Context Protocol) server configurations for security issues. This auto-discovers MCP configs from Claude Desktop, Claude Code, Cursor, Windsurf, VS Code, and project-level config files.

```
vaso mcp scan [options]
```

| Option | Description |
|--------|-------------|
| `-f, --format <format>` | Output format: `terminal` (default), `json`, `sarif`, `markdown` |
| `-o, --output <file>` | Write report to a file instead of stdout |
| `-p, --path <paths...>` | Specific config file paths to scan (skips auto-discovery) |
| `--no-color` | Disable colored terminal output |

Examples:

```bash
# Scan all auto-discovered MCP configs
vaso mcp scan

# Scan a specific config file
vaso mcp scan --path ~/.claude/mcp.json

# Generate JSON report
vaso mcp scan --format json -o mcp-report.json
```

### `vaso mcp list`

List discovered MCP server configurations without running security checks. Useful for verifying which MCP servers VASO can see before running a scan.

```
vaso mcp list [options]
```

| Option | Description |
|--------|-------------|
| `-f, --format <format>` | Output format: `terminal` (default) or `json` |
| `-p, --path <paths...>` | Specific config file paths to scan |

Examples:

```bash
# List all discovered MCP servers
vaso mcp list

# Get machine-readable output
vaso mcp list --format json

# List servers from a specific config
vaso mcp list --path .mcp.json
```

Terminal output shows each server's name, transport type, command/URL, and environment variable names. JSON output returns the full discovery result.

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Scan completed, no critical findings |
| `1` | Critical findings detected (or scan failed) |

This allows VASO to fail CI/CD pipelines when critical issues are found.

## Scoring

VASO produces a 0-100 score with a letter grade:

| Grade | Score Range |
|-------|------------|
| A | 90-100 |
| B | 80-89 |
| C | 70-79 |
| D | 60-69 |
| F | 0-59 |

Penalties:
- **Critical** finding: -12 points
- **Warning** finding: -5 points
- **Info** finding: no penalty

## Security Checks

VASO runs 49 checks organized into 6 categories.

### Configuration (CFG-001 to CFG-015)

Audits agent configuration files for insecure settings.

| ID | Name | Severity | Fixable |
|----|------|----------|---------|
| CFG-001 | Gateway Binding (0.0.0.0) | Critical | Yes |
| CFG-002 | API Key Exposure | Critical | No |
| CFG-003 | File Permissions | Warning | Yes |
| CFG-004 | TLS Not Configured | Warning | No |
| CFG-005 | Missing Shell Allowlist | Warning | Yes |
| CFG-006 | No Workspace Restriction | Warning | No |
| CFG-007 | Webhook Missing Auth | Warning | No |
| CFG-008 | Sandbox Disabled | Critical | Yes |
| CFG-009 | Default/Weak Credentials | Critical | No |
| CFG-010 | No Rate Limiting | Warning | Yes |
| CFG-011 | Node.js CVE-2026-21636 | Warning | No |
| CFG-012 | Auth Bypass Enabled | Critical | Yes |
| CFG-013 | DM Policy Open | Warning | Yes |
| CFG-014 | Tool Policy Permissive | Warning | No |
| CFG-015 | mDNS Full Broadcast | Info | No |

### Skill Code Analysis (SKL-001 to SKL-010)

Static analysis of skill/plugin source code using AST parsing and pattern matching.

| ID | Name | Severity | Method |
|----|------|----------|--------|
| SKL-001 | Data Exfiltration Flow | Critical | AST source-to-sink |
| SKL-002 | Obfuscated Code | Warning | Entropy analysis |
| SKL-003 | Eval/Exec Usage | Critical | AST |
| SKL-004 | Curl-Pipe Execution | Critical | Pattern |
| SKL-005 | Reverse Shell Patterns | Critical | Pattern |
| SKL-006 | Credential Harvesting | Critical | AST + pattern |
| SKL-007 | Prompt Injection in SKILL.md | Warning | Pattern |
| SKL-008 | Suspicious Network Calls | Warning | AST |
| SKL-009 | Crypto Wallet Targeting | Warning | Pattern |
| SKL-010 | Unauthorized FS Access | Warning | AST |

### Indicators of Compromise (IOC-001 to IOC-006)

Matches against known threat intelligence.

| ID | Name | Severity |
|----|------|----------|
| IOC-001 | C2 IP Detection | Critical |
| IOC-002 | Malicious Domains | Critical |
| IOC-003 | File Hash Match | Critical |
| IOC-004 | Malicious Publishers | Critical |
| IOC-005 | Typosquatting | Warning |
| IOC-006 | Skill Name Patterns | Warning |

### Network (NET-001 to NET-004)

Checks for exposed services and network misconfigurations.

| ID | Name | Severity |
|----|------|----------|
| NET-001 | Gateway Internet Exposure | Critical |
| NET-002 | WebSocket Origin Validation | Critical |
| NET-003 | Reverse Proxy Bypass | Warning |
| NET-004 | Port Scan (Agent Services) | Info |

### Runtime (RUN-001 to RUN-004)

Detects persistence mechanisms and runtime threats.

| ID | Name | Severity |
|----|------|----------|
| RUN-001 | Unauthorized LaunchAgents/systemd | Warning |
| RUN-002 | Suspicious Cron Entries | Warning |
| RUN-003 | VS Code Extension Trojans | Critical |
| RUN-004 | Docker Socket Permissions | Warning |

### MCP Server Security (MCP-001 to MCP-010)

Security checks for MCP (Model Context Protocol) server configurations and source code.

| ID | Name | Severity | Fixable |
|----|------|----------|---------|
| MCP-001 | MCP Config Discovery | Info | No |
| MCP-002 | Transport Security | Critical | No |
| MCP-003 | Credential Exposure | Critical | Yes |
| MCP-004 | Overprivileged Tools | Critical | No |
| MCP-005 | Tool Input Injection | Critical | No |
| MCP-006 | Data Exfiltration Risk | Critical | No |
| MCP-007 | Prompt Injection via Tool Results | Warning | No |
| MCP-008 | Server Provenance | Warning/Critical | No |
| MCP-009 | Permission Scope | Warning | No |
| MCP-010 | Rug Pull Risk | Warning | Yes |

MCP-008 severity is dynamic: critical if an IOC match is found, otherwise warning.

## Supported Agents

### OpenClaw

VASO searches the following directories:
- `$OPENCLAW_HOME` (environment variable)
- `~/.openclaw`
- `~/.clawdbot`
- `~/.moltbot`
- `/etc/openclaw`

Config files parsed: `openclaw.json`, `config.yaml`, `config.json`, `gateway.yaml`, `.env`

### NanoClaw

VASO looks for:
- `~/.nanoclaw.env`
- `~/.config/nanoclaw/` (mount allowlist and config)

### PicoClaw

VASO looks for:
- `~/.picoclaw/config.json`
- `~/.picoclaw/auth.json`

### MCP Servers

VASO auto-discovers MCP server configurations from multiple sources:

**Global configs:**
- `~/Library/Application Support/Claude/claude_desktop_config.json` (Claude Desktop, macOS)
- `~/.config/Claude/claude_desktop_config.json` (Claude Desktop, Linux)
- `%APPDATA%\Claude\claude_desktop_config.json` (Claude Desktop, Windows)
- `~/.claude/mcp.json` (Claude Code)
- `~/.cursor/mcp.json` (Cursor)
- `~/.codeium/windsurf/mcp_config.json` (Windsurf)

**Project-level configs:**
- `.mcp.json` (Claude Code project)
- `.cursor/mcp.json` (Cursor project)
- `.windsurf/mcp.json` (Windsurf project)
- `.vscode/mcp.json` (VS Code)
- `mcp.json` (Generic MCP)

You can also point VASO at specific config files with `vaso mcp scan --path <file>`.

## Output Formats

### Terminal (default)

Color-coded, human-readable output with severity icons and a summary score.

### JSON

Structured JSON with the full scan result including per-agent scores, individual check results, and evidence. Useful for programmatic consumption.

```bash
vaso scan --format json | jq '.totalScore'
```

### SARIF

SARIF v2.1.0 output compatible with:
- GitHub Code Scanning (via `github/codeql-action/upload-sarif`)
- GitLab SAST
- VS Code SARIF Viewer extension

```bash
vaso scan --format sarif -o results.sarif
```

### Markdown

Tables and sections formatted for embedding in pull request comments, wiki pages, or documentation.

## Differential Scanning

Track security posture over time and catch regressions or supply chain attacks where a skill is updated maliciously after an initial clean scan.

```bash
# After a clean scan, save the baseline
vaso scan --save-baseline

# On subsequent scans, compare against the baseline
vaso scan --diff
```

The diff output shows:
- **New findings**: issues that appeared since the baseline
- **Resolved**: issues that were fixed since the baseline
- **Unchanged**: issues that persist

Baselines are stored at `~/.vaso/baselines/latest.json`.

## CI/CD Integration

### GitHub Actions

```yaml
name: VASO Security Scan

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 6 * * 1' # Weekly Monday 6am

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-node@v4
        with:
          node-version: '20'

      - name: Install VASO
        run: npm install -g vaso

      - name: Run VASO scan
        run: vaso scan --format sarif -o results.sarif
        continue-on-error: true

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif

      - name: Run VASO scan (JSON)
        run: vaso scan --format json -o results.json
        continue-on-error: true

      - name: Upload scan results
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: vaso-scan-results
          path: |
            results.sarif
            results.json
```

### Generic CI

```bash
# Fail the pipeline on critical findings
vaso scan --format json -o results.json
# Exit code 1 = critical findings detected
```

## Zero-Dependency Quick Scan

For environments without Node.js, use the Bash quick-scan script:

```bash
bash bin/vaso-quick.sh
```

This runs 5 critical checks (gateway binding, API key exposure, file permissions, sandbox status, auth bypass) using only standard Unix tools. No dependencies required.

## Data Storage

| Path | Purpose |
|------|---------|
| `~/.vaso/baselines/` | Saved scan baselines |
| `~/.vaso/backups/<timestamp>/` | File backups before remediation |

## Safety Guarantees

- VASO never executes scanned code (all analysis is purely static)
- No data leaves the machine unless you explicitly pipe output elsewhere
- Remediation always creates backups before modifying files
- The scanner runs read-only by default; only `vaso fix` modifies files
