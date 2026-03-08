# VASO

**VULNEX Agent Security Observer** — agent-agnostic security scanner for AI agent deployments.

<!-- badges -->

## Overview

VASO scans AI agent frameworks and MCP server configurations for security misconfigurations, malicious code, and known threats. It runs 113 checks across 6 agent frameworks, using AST-based static analysis (not regex) for accurate results without ever executing scanned code.

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

- **OpenClaw** — `~/.openclaw`, `~/.clawdbot`, `~/.moltbot`, `/etc/openclaw`
- **NanoClaw** — `~/.nanoclaw.env`, `~/.config/nanoclaw/`
- **PicoClaw** — `~/.picoclaw/`
- **IronClaw**, **Nanobot**, **ZeroClaw** — additional agent frameworks
- **MCP Servers** — Claude Desktop, Claude Code, Cursor, Windsurf, VS Code, project-level configs

## Security Checks

113 checks organized into 11 categories:

| Category | IDs | Count | Description |
|----------|-----|-------|-------------|
| Configuration | CFG-001–015 | 15 | Gateway binding, API keys, TLS, permissions, sandbox |
| Skill Code | SKL-001–012 | 12 | AST data-flow, obfuscation, eval/exec, reverse shells |
| IOC Matching | IOC-001–008 | 8 | C2 IPs, malicious domains, typosquatting, file hashes |
| Network | NET-001–005 | 5 | Gateway exposure, WebSocket origins, proxy bypass |
| Runtime | RUN-001–005 | 5 | LaunchAgents, cron, Docker socket, VS Code trojans |
| Policy | POL-001–005 | 5 | DM policy, tool policy, sandbox compliance |
| MCP Server | MCP-001–020 | 20 | Transport security, credential exposure, tool injection, toxic flows, rug pull |
| Advisory | ADV-001–005 | 5 | Vulnerability/CVE detection with version awareness |
| Agent-Specific | Various | 38 | Per-framework checks (IronClaw, Nanobot, ZeroClaw) |

## Output Formats

```bash
vaso scan                              # Terminal (default) — color-coded with score
vaso scan --format json -o report.json # JSON — structured, machine-readable
vaso scan --format sarif -o results.sarif  # SARIF — GitHub Code Scanning compatible
vaso scan --format markdown -o report.md   # Markdown — for PR comments
vaso scan --format html -o report.html     # HTML — standalone report
```

## Scoring

VASO produces a 0–100 score with a letter grade (A–F). Critical findings deduct 12 points, warnings deduct 5.

## CI/CD Integration

VASO ships with a ready-made workflow at `.github/workflows/vaso-scan.yml`. For custom setups:

```yaml
- name: Install VASO
  run: npm install -g vaso

- name: Run VASO scan
  run: vaso scan --format sarif -o results.sarif
  continue-on-error: true

- name: Upload SARIF
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
