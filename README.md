# VASO

**VULNEX Agent Security Observer** — agent-agnostic security scanner for AI agent deployments.

<!-- badges -->

## Overview

VASO scans AI agent frameworks, interactive coding agents, desktop AI apps, and MCP server configurations for security misconfigurations, malicious code, and known threats. It runs 251 checks across 18 agents (9 autonomous frameworks + 7 interactive coding agents + Claude Desktop + ChatGPT Desktop) plus MCP-server scanning, using AST-based static analysis (not regex) for accurate results without ever executing scanned code.

## Installation

VASO is distributed from GitHub. The npm name `vaso` is held by an unrelated package; do not install that.

```bash
# One-liner (Linux / macOS / WSL)
curl -fsSL https://raw.githubusercontent.com/vulnex/vaso/main/install.sh | bash

# Or directly via npm from GitHub
npm install -g github:vulnex/vaso#v0.4.2
```

Requires Node.js 20+.

## Quick Start

```bash
# Scan all detected AI agents
vaso scan

# List installed agents
vaso detect

# Scan MCP server configs
vaso mcp scan
```

Exit code 1 means critical findings were detected — use this to fail CI pipelines.

## Remote / Fleet Scanning

VASO can scan remote hosts over SSH or from pre-collected snapshots — no Node.js required on the target. A static Go probe binary is pushed on demand, runs once, and is removed. See [`doc/network-scanning-guide.md`](doc/network-scanning-guide.md) for the full workflow.

```bash
# Scan one remote host
vaso scan --host root@10.0.0.5

# Scan a fleet (parallel, with retry on transient SSH failures)
vaso scan --inventory hosts.yaml --parallel 20 --ssh-retries 2

# Collect snapshots once, re-scan offline against new baselines
vaso scan --inventory hosts.yaml --save-snapshot ./snapshots/
vaso scan --snapshot ./snapshots/prod-agent-01.json --diff
```

## Commands

| Command | Description |
|---------|-------------|
| `vaso scan` | Scan installed agents and report findings |
| `vaso detect` | List detected agent installations |
| `vaso fix` | Auto-remediate fixable findings |
| `vaso visualize` | Emit USecVisLib config files for visualization |
| `vaso update` | Reload IOC threat intelligence database |
| `vaso mcp scan` | Scan MCP server configurations |
| `vaso mcp list` | List discovered MCP servers |
| `vaso skill audit <path>` | Audit a skill directory before installing |
| `vaso plugin install <path>` | Install a user plugin |
| `vaso plugin uninstall <name>` | Remove a user plugin |
| `vaso plugin status` | List installed plugins |
| `vaso ext list` | List available extensions |
| `vaso ext info <name>` | Show extension details |

See [doc/user-guide.md](doc/user-guide.md) for full option reference.

## Supported Agents

**Autonomous frameworks**

- **OpenClaw** — `~/.openclaw`, `~/.clawdbot`, `~/.moltbot`, `/etc/openclaw`
- **NanoClaw** — `~/.nanoclaw.env`, `~/.config/nanoclaw/`
- **PicoClaw** — `~/.picoclaw/`
- **IronClaw** — `~/.ironclaw/` (TOML, gRPC gateway)
- **Nanobot** — `~/.nanobot/` (Discord/Slack bot framework)
- **ZeroClaw** — `~/.zeroclaw/` (Composio integration)
- **NemoClaw** — `~/.nemoclaw/` (NVIDIA NIM, GPU isolation)
- **Hermes** — `~/.hermes/` (API-server gateway model)
- **Lyrie** — `~/.lyrie/` (Bun turborepo, Rust Shield Layer 1, 10-channel gateway)

**Coding agents**

- **Claude Code** — `~/.claude/`, `~/.claude.json`, project-level `.claude/`
- **Claude Desktop** — `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS), `%APPDATA%\Claude\claude_desktop_config.json` (Windows); MCPB extensions
- **ChatGPT Desktop** — `/Applications/ChatGPT.app` + `~/Library/Application Support/com.openai.chat/`; preferences plist (macOS only)
- **Codex** — `~/.codex/{config.toml,auth.json}`
- **OpenCode** — XDG paths (`$XDG_CONFIG_HOME/opencode/`, `$XDG_DATA_HOME/opencode/`)
- **Gemini CLI** — `~/.gemini/` (settings.json + OAuth credential files)
- **Qwen Code** — `~/.qwen/` (multi-provider auth: OpenAI / Anthropic / Gemini / Dashscope / Bailian)
- **GitHub Copilot CLI** — `~/.copilot/` + workspace `.mcp.json` + `.github/lsp.json`
- **Cursor CLI** — `~/.cursor/` (cli-config.json + mcp.json)

**MCP servers** — Claude Desktop, Claude Code, Cursor, Windsurf, VS Code, project-level configs

## Security Checks

252 checks organized into 16 categories:

| Category | IDs | Count | Description |
|----------|-----|-------|-------------|
| Configuration | CFG-001–024 | 24 | Gateway binding, API keys, TLS, permissions, sandbox, NemoClaw hardening |
| Skill Code | SKL-001–012 | 12 | AST data-flow, obfuscation, eval/exec, reverse shells |
| IOC Matching | IOC-001–008 | 8 | C2 IPs, malicious domains, typosquatting, file hashes |
| Network | NET-001–005 | 5 | Gateway exposure, WebSocket origins, proxy bypass |
| Runtime | RUN-001–005 | 5 | LaunchAgents, cron, Docker socket, VS Code trojans |
| Policy | POL-001–005 | 5 | DM policy, tool policy, sandbox compliance |
| MCP Server | MCP-001–023 | 23 | Transport security, credential exposure, tool injection, toxic flows, rug pull, stdio shell-c, world-writable command paths, streamable-HTTP origin pinning |
| Advisory | ADV-001–005 | 5 | Vulnerability/CVE detection with version awareness |
| Coding Agent | CC, CD, CG, CDX, OPC, GEM, QC, CUR, GHC | 87 | Claude Code (12), Claude Desktop (10), ChatGPT Desktop (6), Codex (9), OpenCode (12), Gemini CLI (10), Qwen Code (10), Cursor CLI (10), GitHub Copilot CLI (8) — sandbox/approval policy, plaintext credentials, MCP pinning, broad allow rules, memory-file secrets, transport security |
| Agent-Specific | OC, NC, IC, NB, ZC, LY, HM | 78 | Per-framework checks (OpenClaw 7, NanoClaw 5, IronClaw 12, Nanobot 12, ZeroClaw 14, Lyrie 18, Hermes 10) |

Server-only checks (gateway/network/runtime concepts) are automatically excluded for coding agents to avoid false positives — interactive coding CLIs have a different threat model than autonomous server agents.

## Output Formats

```bash
vaso scan                              # Terminal (default) — color-coded with score
vaso scan --format json -o report.json # JSON — structured, machine-readable
vaso scan --format sarif -o results.sarif  # SARIF — GitHub Code Scanning compatible
vaso scan --format markdown -o report.md   # Markdown — for PR comments
vaso scan --format html -o report.html     # HTML — standalone report
vaso scan --format csv -o results.csv      # CSV — one row per finding, for SIEM ingestion
vaso scan --format junit -o results.xml    # JUnit XML — for CI test-result reporters
```

## Scoring

VASO produces a 0–100 score with a letter grade (A–F). Critical findings deduct 12 points, warnings deduct 5.

## CI/CD Integration

### GitHub Action

The simplest path — drop one step into any workflow:

```yaml
- uses: vulnex/vaso@v1
  with:
    fail-on: critical          # or warning, info, none
    format: sarif              # sarif, json, markdown, html, terminal
    # output: vaso-results.sarif  (default: vaso-results.<ext>)
    # agent: claude-code           (default: scan all detected agents)
    # version: latest               (npm dist-tag or x.y.z)
    # upload-sarif: 'true'          (auto-uploads to Code Scanning)
```

The action installs the requested VASO version, runs the scan, and (when `format: sarif`) uploads the report to GitHub Code Scanning. Exit codes follow `--fail-on`: a `critical` threshold (default) fails the build only on critical findings; pass `none` to never fail.

### Manual workflow

```yaml
- name: Install VASO
  run: npm install -g github:vulnex/vaso#v0.4.2

- name: Run VASO scan
  run: vaso scan --format sarif -o results.sarif --fail-on critical

- name: Upload SARIF
  if: always()
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

## Differential Scanning

Track security posture over time:

```bash
vaso scan --save-baseline    # Save after a clean scan
vaso scan --diff             # Compare against baseline on subsequent scans
```

## Visualizations

`vaso visualize` emits [USecVisLib](https://github.com/vulnex/usecvislib) config files (TOML by default; JSON/YAML available) for three diagram types: per-installation **attack tree**, per-installation **privilege gradient** (architecture-specific — NemoClaw GPU isolation, Claude Code MCP transport, etc.), and a whole-scan **component diagram**.

```bash
# Run a fresh scan and write the bundle
vaso visualize -o ./vis/

# Or replay a saved scan result
vaso scan -f json -o scan.json
vaso visualize -i scan.json -o ./vis/

# Render with USecVisLib (commands also listed in the bundle README)
usecvis -m 0 -i ./vis/openclaw-attack-tree.toml -o tree -f png
usecvis -m 6 -i ./vis/openclaw-privilege-gradient.toml -o gradient -f png
usecvis -m 7 -i ./vis/topology.toml -o topology -f png
```

VASO never bundles, sidecars, or calls a USecVisLib server — the contract between the two tools is a static config file. Users render externally with whichever USecVisLib mode (CLI, REST, or MCP) they prefer.

## Zero-Dependency Quick Scan

For environments without Node.js, run 5 critical checks with pure Bash:

```bash
bash bin/vaso-quick.sh
```

## Plugin System

VASO supports user plugins in `~/.vaso/plugins/`. Plugins can add custom checks, output formatters, and agent adapters. See [doc/development-guide.md](doc/development-guide.md) for the plugin API.

## Documentation

- [User Guide](doc/user-guide.md) — full command reference and configuration
- [Network Scanning Guide](doc/network-scanning-guide.md) — SSH, inventory, snapshot, and fleet workflows
- [Development Guide](doc/development-guide.md) — contributing and plugin development
- [Testing Guide](doc/testing-guide.md) — test suite and CI setup

## License

MIT
