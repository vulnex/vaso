# VASO User Guide

VASO (VULNEX Agent Security Observer) is a security scanner for AI agent deployments. It detects misconfigurations, malicious skills, known threats, and runtime vulnerabilities across nine autonomous agent frameworks (OpenClaw, NanoClaw, PicoClaw, IronClaw, Nanobot, ZeroClaw, NemoClaw, Hermes, Lyrie), seven interactive coding agents (Claude Code, Codex, OpenCode, Gemini CLI, Qwen Code, GitHub Copilot CLI, Cursor CLI), the Claude Desktop and ChatGPT desktop apps, and MCP (Model Context Protocol) server configurations.

## Installation

VASO is distributed from GitHub. The npm name `vaso` is held by an unrelated package; do not install that.

```bash
# One-liner (Linux / macOS / WSL) — recommended
curl -fsSL https://raw.githubusercontent.com/vulnex/vaso/main/install.sh | bash

# Or install the prebuilt release tarball directly with npm
npm install -g https://github.com/vulnex/vaso/releases/download/v0.4.14/vaso-0.4.14.tgz
```

Requirements: Node.js 20 or later.

Install the release **tarball**, not `npm install -g github:vulnex/vaso#<tag>` — on npm 11+ the global git-dependency install path mishandles the package and leaves an unusable install. The tarball is prebuilt and installs with no build step.

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
| `-a, --agent <type>` | Scan a specific agent: `openclaw`, `nanoclaw`, `picoclaw`, `ironclaw`, `nanobot`, `zeroclaw`, `nemoclaw`, `hermes`, `lyrie`, `claude-code`, `claude-desktop`, `chatgpt-desktop`, `codex`, `opencode`, `gemini-cli`, `qwen-code`, `copilot-cli`, or `cursor-cli` |
| `-f, --format <format>` | Output format: `terminal` (default), `json`, `sarif`, `markdown`, `html`, `csv`, `junit` |
| `-o, --output <file>` | Write report to a single file instead of stdout |
| `--output-dir <dir>` | Multi-host: write one file per host as `<dir>/<hostname>.<ext>` (mutually exclusive with `-o`) |
| `--save-baseline` | Save current results as a baseline for future comparison |
| `--diff` | Compare results against the last saved baseline |
| `--all-users` | Scan all user accounts (requires root/sudo) |
| `--fail-on <severity>` | Exit non-zero on findings of this severity or higher: `critical` (default), `warning`, `info`, or `none` |
| `--silent` | Suppress all stdout/stderr chatter; requires `-o` or `--output-dir` |
| `--no-color` | Disable colored terminal output |
| `--host <target...>` | Scan one or more remote hosts via SSH (`user@host[:port]`). Variadic. |
| `--inventory <path>` | YAML file listing hosts to scan |
| `--ssh-key <path>` | SSH identity file for remote connections |
| `--ssh-timeout <seconds>` | Per-attempt SSH connection timeout (default 60) |
| `--ssh-retries <n>` | Additional SSH attempts after the first failure, with exponential backoff (default 0) |
| `--parallel <n>` | Max hosts to scan concurrently (default 5) |
| `--sudo` | Attempt sudo escalation on remote hosts |
| `--snapshot <path>` | Scan from a pre-collected probe snapshot file (offline / airgapped) |
| `--save-snapshot <dir>` | When scanning over SSH, write each host's snapshot to `<dir>/<hostname>.json` |

`--debug` is also available globally to print full stack traces on errors. For remote and fleet scanning details, see [`network-scanning-guide.md`](network-scanning-guide.md).

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

# Fail CI on any warning or critical finding
vaso scan --fail-on warning

# Scan a single remote host over SSH
vaso scan --host root@10.0.0.5

# Scan a fleet from an inventory file, 20 in parallel, retry transient failures
vaso scan --inventory hosts.yaml --parallel 20 --ssh-retries 2

# Collect snapshots once, re-scan offline against new baselines
vaso scan --inventory hosts.yaml --save-snapshot ./snapshots/
vaso scan --snapshot ./snapshots/prod-agent-01.json --diff
```

### `vaso detect`

Lists installed AI agents without running any security checks. Useful for verifying which agents VASO can see before running a full scan.

```
vaso detect [options]
```

| Option | Description |
|--------|-------------|
| `-a, --agent <type>` | Detect a specific agent only: `openclaw`, `nanoclaw`, `picoclaw`, `ironclaw`, `nanobot`, `zeroclaw`, `nemoclaw`, `hermes`, `lyrie`, `claude-code`, `claude-desktop`, `chatgpt-desktop`, `codex`, `opencode`, `gemini-cli`, `qwen-code`, `copilot-cli`, or `cursor-cli` |
| `-f, --format <format>` | Output format: `terminal` (default) or `json` |
| `-o, --output <file>` | Write report to a file instead of stdout |
| `--all-users` | Detect across all user accounts (requires root/sudo) |
| `--verbose` | Show the search paths checked for each adapter |
| `--silent` | Suppress all stdout/stderr chatter; requires `-o` |
| `--host <target...>` | Detect on one or more remote hosts via SSH (`user@host[:port]`). Variadic. |
| `--inventory <path>` | YAML file listing hosts to detect against |
| `--ssh-key <path>` | SSH identity file for remote connections |
| `--ssh-timeout <seconds>` | Per-attempt SSH connection timeout (default 60) |
| `--ssh-retries <n>` | Additional SSH attempts after the first failure (default 0) |
| `--parallel <n>` | Max hosts to detect concurrently (default 5) |
| `--snapshot <path>` | Detect from a pre-collected probe snapshot file |
| `--save-snapshot <dir>` | When detecting over SSH, write each host's snapshot to `<dir>/<hostname>.json` |

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
| `-f, --format <format>` | Output format: `terminal` (default), `json`, `sarif`, `markdown`, `html`, `csv`, `junit` |
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

### `vaso visualize`

Emit USecVisLib config files (TOML/JSON/YAML) for rendering architecture diagrams of the scan result. Use these with the external `usecvis` renderer — VASO never depends on Python, Graphviz, or a network-reachable server at scan time.

```
vaso visualize [options]
```

| Option | Description |
|--------|-------------|
| `-i, --input <file>` | Use an existing scan-result JSON instead of running a fresh scan |
| `-o, --output <dir>` | Output directory for the bundle (default `./vaso-visualizations`) |
| `--vis-format <format>` | Config file format: `toml` (default), `json`, or `yaml` |
| `--diagrams <list>` | Comma-separated diagram types: `attack-tree`, `privilege-gradient`, `component` |
| `-a, --agent <type>` | Scan a specific agent only when running a fresh scan |
| `--all-users` | Scan all user accounts (requires root/sudo) |

Examples:

```bash
# Run a fresh scan and emit all three diagram types
vaso visualize

# Reuse an existing scan result
vaso visualize -i scan.json -o ./diagrams

# Only emit the attack-tree diagram in YAML
vaso visualize --diagrams attack-tree --vis-format yaml
```

The output directory contains one config file per (installation × diagram) plus a `README.md` with copy-paste `usecvis` commands.

### `vaso update`

Reload the IOC (Indicators of Compromise) and advisory threat-intelligence databases. Both feeds are signed with a pinned Ed25519 key (`src/ioc/public-key.ts`) and rejected on version rollback — see `SECURITY.md`. The bundled databases remain the offline baseline; `vaso update` only refreshes the in-memory state with newer signed data.

```bash
vaso update           # Fetch latest signed feeds
vaso update --force   # Update even if feeds are not stale
vaso update --url <url>  # Custom feed URL (must still be signed with the pinned key)
```

### `vaso mcp scan`

Scan MCP (Model Context Protocol) server configurations for security issues. This auto-discovers MCP configs from Claude Desktop, Claude Code, Cursor, Windsurf, VS Code, and project-level config files.

```
vaso mcp scan [options]
```

| Option | Description |
|--------|-------------|
| `-f, --format <format>` | Output format: `terminal` (default), `json`, `sarif`, `markdown`, `html`, `csv`, `junit` |
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

### `vaso plugin`

Install or remove the VASO security plugin for an agent framework (OpenClaw, NanoClaw, PicoClaw). When installed, the plugin runs a scan as a `before_agent_start` hook so the agent refuses to launch with critical findings present.

```bash
vaso plugin install -a openclaw [--force]
vaso plugin uninstall -a openclaw
vaso plugin status [-a openclaw] [-f terminal|json]
```

| Subcommand | Purpose |
|------------|---------|
| `install` | Install the plugin into the agent's plugin directory |
| `uninstall` | Remove the plugin |
| `status` | Show install state for one or all supported agents |

### `vaso ext`

Manage user plugins — drop-in `.js` / `.mjs` files in `~/.vaso/plugins/` that register custom checks, adapters, or reporters. See `examples/plugins/` for working examples.

```bash
vaso ext list [-f terminal|json]
vaso ext info <name>
```

User plugins are loaded automatically on every CLI invocation; errors are isolated so a broken plugin can't crash the scan.

### `vaso probe`

Advanced — manage probe snapshots for remote scanning. The probe is normally push-deployed automatically by `vaso scan --host` / `--inventory`; these commands let you inspect what the probe will collect or validate a snapshot file by hand.

```bash
vaso probe manifest               # Print the manifest the probe will use
vaso probe validate <snapshot>    # Validate a probe snapshot JSON file
```

See [`network-scanning-guide.md`](network-scanning-guide.md) for the full SSH workflow.

## Exit Codes

`vaso scan` exits non-zero when findings reach the threshold set by `--fail-on`:

| Code | Meaning |
|------|---------|
| `0` | Scan completed; no findings at or above the `--fail-on` threshold |
| `1` | Findings at or above the threshold (or the scan failed for another reason) |
| `2` | Invalid CLI arguments (e.g. `--silent` without an output destination, `--parallel 0`) |

`--fail-on` accepts `critical` (default), `warning`, `info`, or `none`. Use `--fail-on none` to never fail on findings — useful for scans that only produce reports.

```bash
vaso scan --fail-on critical    # Default — only critical findings fail CI
vaso scan --fail-on warning     # Warning or critical fails CI
vaso scan --fail-on none        # Always exit 0 unless the scan itself errors
```

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

VASO runs **264 checks across 16 categories**.

| Category | IDs | Count | Scope |
|----------|-----|-------|-------|
| Configuration | CFG-001–024 | 24 | Gateway binding, API keys, TLS, permissions, sandbox, NemoClaw hardening |
| Skill Code | SKL-001–012 | 12 | AST data-flow, obfuscation, eval/exec, reverse shells |
| IOC Matching | IOC-001–008 | 8 | C2 IPs, malicious domains, typosquatting, file hashes |
| Network | NET-001–005 | 5 | Gateway exposure, WebSocket origins, proxy bypass |
| Runtime | RUN-001–005 | 5 | LaunchAgents, cron, Docker socket, VS Code trojans |
| Policy | POL-001–005 | 5 | DM policy, tool policy, sandbox compliance |
| MCP Server | MCP-001–035 | 35 | Transport security, credentials, tool injection, toxic flows, rug pull, OAuth 2.1, stdio shell-c, world-writable command paths, streamable-HTTP origin pinning, tool-description poisoning, cross-server tool-name collision, slash-command overlap, remote-server-without-auth, filesystem sensitive-path scope, vulnerable/rolled-back version, config drift, untrusted installer source, env-dump tool, long-lived token, prompt-injection directives in tool output, obfuscated/encoded server source; opt-in npm package source resolution (`--resolve-packages`); OWASP MCP Top 10 mapping |
| Advisory | ADV-001–005 | 5 | Vulnerability/CVE detection with version awareness |
| OpenClaw | OC-* | 7 | Sub-agent config downgrade, legacy bot dirs, `OPENCLAW_HOME` redirect, profile downgrade, memory file perms, `/etc/openclaw` writable |
| NanoClaw | NC-001–005 | 5 | Overbroad mount allowlist, allowlist-file writable, `NANOCLAW_HOME` redirect, public listener bind, skills-dir writable |
| IronClaw | IC-001–012 | 12 | Webhook bind, sandbox, auto-approve tools |
| Nanobot | NB-001–012 | 12 | Channel allow, shell filtering, memory injection |
| ZeroClaw | ZC-001–014 | 14 | API keys, autonomy mode, filesystem access |
| Lyrie | LY-001–018 | 18 | Shield mode/binary, multi-channel DM pairing, WebChat exposure, edit-ledger perms, executable skills, cross-agent migration imports, dev-mode footguns |
| Hermes | HM-001–010 | 10 | Plaintext API keys, env/credentials perms, API-server bind without auth, permissive CORS, plaintext inference endpoints, approvals-off, Tirith pre-exec scanner state, MCP stdio shell-c / unpinned packages |
| Coding Agent | CC, CD, CG, CDX, OPC, GEM, QC, CUR, GHC | 87 | Claude Code (12), Claude Desktop (10), ChatGPT Desktop (6), Codex (9), OpenCode (12), Gemini CLI (10), Qwen Code (10), Cursor CLI (10), GitHub Copilot CLI (8): sandbox/approval policy, plaintext credentials, MCP pinning, broad allow rules, memory-file secrets, transport security |

Server-side checks (CFG, NET, RUN, POL) are auto-excluded for coding agents since their threat model differs from server frameworks.

## Supported Agents

VASO ships eighteen adapters. Each implements `detect()`, `getConfigPaths()`, `getSkillsDir()`, and `getGatewayInfo()` against its framework's on-disk layout.

### Autonomous frameworks

| Adapter | Config locations | Formats |
|---------|------------------|---------|
| OpenClaw | `$OPENCLAW_HOME`, `~/.openclaw`, `~/.clawdbot`, `~/.moltbot`, `/etc/openclaw` | JSON, YAML, ENV |
| NanoClaw | `~/.nanoclaw.env`, `~/.config/nanoclaw/` | JSON, ENV |
| PicoClaw | `~/.picoclaw/config.json`, `~/.picoclaw/auth.json` | JSON |
| IronClaw | `~/.ironclaw/`, `/etc/ironclaw/` | TOML |
| Nanobot | `~/.nanobot/`, project-local | JSON |
| ZeroClaw | `~/.zeroclaw/`, `/etc/zeroclaw/` | TOML |
| NemoClaw | `~/.nemoclaw/`, `/etc/nemoclaw/` | JSON, YAML |
| Hermes | `~/.hermes/`, `/etc/hermes/` | YAML, ENV |
| Lyrie | `~/.lyrie/` (Bun turborepo with Rust Shield, 10-channel gateway, MCP client+server) | ENV |

### Coding agents

| Adapter | Config locations | Formats |
|---------|------------------|---------|
| Claude Code | `~/.claude/`, `~/.claude.json`, project `.claude/` | JSON |
| Claude Desktop | `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS), `%APPDATA%\Claude\claude_desktop_config.json` (Windows); MCPB extensions under `Claude Extensions/` | JSON |
| ChatGPT Desktop | `/Applications/ChatGPT.app` + `~/Library/Application Support/com.openai.chat/`; preferences in `~/Library/Preferences/com.openai.chat*.plist` (macOS only) | plist |
| Codex | `~/.codex/config.toml`, `~/.codex/auth.json` | TOML, JSON |
| OpenCode | `$XDG_CONFIG_HOME/opencode/opencode.json[c]`, `$XDG_DATA_HOME/opencode/auth.json` | JSON, JSONC |
| Gemini CLI | `~/.gemini/settings.json`, OAuth credential files (`oauth_creds.json`, `google_accounts.json`, `mcp-oauth-tokens.json`); project `.gemini/` | JSONC |
| Qwen Code | `~/.qwen/settings.json` (multi-provider auth: OpenAI/Anthropic/Gemini/Dashscope/Bailian); project `.qwen/` | JSONC |
| GitHub Copilot CLI | `~/.copilot/config.json`, `settings.json`, `command-history-state.json`, `session-state/`; workspace `.mcp.json` + `.github/lsp.json` | JSONC |
| Cursor CLI | `~/.cursor/cli-config.json`, `~/.cursor/mcp.json` | JSON |

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

Seven formats are supported via `-f / --format`. The natural extension is used when writing to `--output-dir`.

### Terminal (default)

Color-coded, human-readable output with severity icons and a summary score. Use `--no-color` to disable ANSI codes when piping into a log file.

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

### HTML

Self-contained, XSS-safe HTML — single file with inline styles, no external assets. Good for archiving in artifact stores or attaching to incident tickets.

```bash
vaso scan --format html -o report.html
```

### CSV

One row per finding, designed for SIEM / data-warehouse ingestion. Columns include `id`, `name`, `severity`, `category`, `agent`, `passed`, `message`, `file`, `line`.

```bash
vaso scan --format csv -o findings.csv
```

### JUnit

JUnit XML — each check becomes a test case (passing or failing). Compatible with the test-result UIs in GitHub Actions, GitLab CI, Jenkins, CircleCI, etc.

```bash
vaso scan --format junit -o vaso-tests.xml
```

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
        run: npm install -g https://github.com/vulnex/vaso/releases/download/v0.4.14/vaso-0.4.14.tgz

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

For fast triage or environments without Node.js, use the Bash quick-scan script. Installed via npm, it's symlinked onto your PATH alongside `vaso`:

```bash
vaso-quick
```

This runs 5 critical checks (gateway binding, API key exposure, file permissions, sandbox status, auth bypass) using only standard Unix tools. No Node.js or npm dependencies required at runtime.

You can also run the script directly without installing anything — fetch it once and execute:

```bash
curl -fsSL https://raw.githubusercontent.com/vulnex/vaso/main/bin/vaso-quick.sh | bash
```

## Data Storage

VASO keeps all local state under `~/.vaso/`:

| Path | Purpose |
|------|---------|
| `~/.vaso/baselines/` | Saved scan baselines for `--save-baseline` / `--diff` |
| `~/.vaso/backups/<timestamp>/` | File backups before `vaso fix` modifies anything |
| `~/.vaso/mcp-tool-baselines/` | Per-server tool-definition baselines for MCP-020 rug-pull detection (keyed by hostname + source) |
| `~/.vaso/plugins/` | User-plugin drop-in directory (`vaso ext`) |
| `~/.vaso/plugin-config.json` | Agent-plugin install state (`vaso plugin install/uninstall/status`) |
| `~/.vaso/ioc/` | IOC feed cache + metadata fetched by `vaso update` |
| `~/.vaso/advisory/` | Advisory/CVE feed cache + metadata fetched by `vaso update` |

Nothing under `~/.vaso/` leaves the machine. The only outbound network call VASO ever makes is `vaso update` against the signed feed URL.

## Safety Guarantees

- VASO never executes scanned code (all analysis is purely static)
- No data leaves the machine unless you explicitly pipe output elsewhere
- Remediation always creates backups before modifying files
- The scanner runs read-only by default; only `vaso fix` modifies files
