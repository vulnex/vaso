# VASO

**VULNEX Agent Security Observer** — agent-agnostic security scanner for AI agent deployments.

<!-- badges -->

## Overview

VASO scans AI agent frameworks, interactive coding agents, and MCP server configurations for security misconfigurations, malicious code, and known threats. It runs 146 checks across 10 agents (8 autonomous frameworks + Claude Code + Codex), using AST-based static analysis (not regex) for accurate results without ever executing scanned code.

## Installation

```bash
npm install -g vaso
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
- **Codex** — `~/.codex/{config.toml,auth.json}`

**MCP servers** — Claude Desktop, Claude Code, Cursor, Windsurf, VS Code, project-level configs

## Security Checks

175 checks organized into 15 categories:

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
| Coding Agent | CC-001–012, CDX-001–009 | 21 | Claude Code (12): bypassPermissions, broad Bash allow, unsafe hooks, plaintext keys, MCP pinning, project-MCP auto-trust, helper perms, missing deny rules, additionalDirectories, status-line safety, sub-agent prompt injection, CLAUDE.md secrets. Codex (9): approval policy, sandbox mode, auth file perms, MCP pinning, shell-env policy, trusted-projects scope, AGENTS.md secrets, profile downgrade, unsafe notify command |
| Agent-Specific | IC, NB, ZC, LY | 56 | Per-framework checks (IronClaw 12, Nanobot 12, ZeroClaw 14, Lyrie 18) |

Server-only checks (gateway/network/runtime concepts) are automatically excluded for coding agents to avoid false positives — Claude Code and Codex have a different threat model than autonomous server agents.

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
  run: npm install -g vaso

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
- [Development Guide](doc/development-guide.md) — contributing and plugin development
- [Testing Guide](doc/testing-guide.md) — test suite and CI setup

## License

MIT
