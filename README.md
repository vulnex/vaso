<p align="center">
  <img src="images/vaso_logo.png" alt="VASO logo" width="320">
</p>

# VASO

**VULNEX Agent Security Observer** — agent-agnostic security scanner for AI agent deployments.

<!-- badges -->

## Overview

VASO scans AI agent frameworks, interactive coding agents, desktop AI apps, and MCP server configurations for security misconfigurations, malicious code, and known threats. It runs 368 checks across 26 agents (10 autonomous frameworks + the NVIDIA OpenShell sandbox runtime + 10 interactive coding agents + 5 agentic desktop apps) plus MCP-server scanning. Analysis is static: Babel AST data-flow tracing for skill and MCP server code, plus pattern and entropy matching for configs and secrets. VASO never executes the code it scans.

## Installation

VASO is distributed from GitHub. The npm name `vaso` is held by an unrelated package; do not install that.

```bash
# Recommended (Linux / macOS / WSL): installs the latest release tarball
curl -fsSL https://raw.githubusercontent.com/vulnex/vaso/main/install.sh | bash

# Alternative: download the release tarball and install it with npm
curl -fLO https://github.com/vulnex/vaso/releases/download/v1.4.3/vaso-1.4.3.tgz
npm install -g ./vaso-1.4.3.tgz
```

Requires Node.js 20+. Download the tarball before installing it: npm 12 refuses tarball URLs by default (`allow-remote=none`). Set `VASO_VERSION=v1.4.3` in front of `bash` to make the installer pick a specific release.

> **Note:** install the release **tarball**, not `npm install -g github:vulnex/vaso#<tag>`. On npm 11+, the global git-dependency install path mishandles the package and leaves an unusable install; the prebuilt tarball has no build step and installs cleanly.

### Build from source

For development, or to install from a local checkout:

```bash
git clone https://github.com/vulnex/vaso.git
cd vaso
npm install
npm run build           # produces dist/cli.js
npm link                # optional: put `vaso` on PATH globally
```

Without `npm link`, run the CLI directly with `./bin/vaso`. Other useful scripts: `npm run dev` (rebuild on change), `npm test` (unit), `npm run test:e2e`, `npm run lint` (`tsc --noEmit`).

### Uninstall

```bash
npm uninstall -g vaso
rm -rf ~/.vaso    # optional: baselines, fix backups, feed cache, plugins, rules (see "Files VASO keeps")
```

Remove `~/.vaso` only if you no longer need its fix backups: `vaso fix --rollback` restores from them.

## Quick Start

```bash
# Scan all detected AI agents
vaso scan

# List installed agents
vaso detect

# Scan MCP server configs
vaso mcp scan
```

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | Clean: no findings at or above the `--fail-on` level (default `critical`) |
| 1 | Findings at or above `--fail-on` |
| 2 | VASO could not run: invalid usage, unreadable snapshot or inventory, a report that could not be written, or an internal error |
| 3 | Scan incomplete: a remote host could not be scanned, or a check errored, so findings may be missing |

Code 3 takes precedence over 1, so CI can tell "not scanned" from "findings". `--fail-on none` never returns 1. `vaso detect` also returns 3 when a remote host could not be reached. If a scan fails or finds nothing you expected, see [Troubleshooting](doc/user-guide.md#troubleshooting).

## Remote / Fleet Scanning

VASO can scan remote hosts over SSH or from pre-collected snapshots — no Node.js required on the target. A static Go probe binary is pushed on demand, runs once, and is removed. The probe matching the remote's OS/arch is fetched and SHA-256-verified automatically on first use, then cached under `~/.vaso/probe/` — so remote scanning works straight away whether you installed or cloned VASO, with no Go toolchain needed. See [`doc/network-scanning-guide.md`](doc/network-scanning-guide.md) for the full workflow.

```bash
# Scan one remote host
vaso scan --host root@10.0.0.5

# Scan a fleet (parallel, with retry on transient SSH failures)
vaso scan --inventory hosts.yaml --parallel 20 --ssh-retries 2

# Collect snapshots once, re-scan offline against new baselines
vaso scan --inventory hosts.yaml --save-snapshot ./snapshots/
vaso scan --snapshot ./snapshots/prod-agent-01.json --diff
```

Remote scans copy configuration from the target, but not everything: conversation history and token stores are collected as file metadata only, and the probe disguises secrets in the files it ships. See [Privacy](doc/network-scanning-guide.md#privacy) in the network scanning guide for what is collected and what never leaves the host.

## Commands

| Command | Description |
|---------|-------------|
| `vaso scan` | Scan installed agents and report findings |
| `vaso detect` | List detected agent installations, their skills directories and skills |
| `vaso fix` | Auto-remediate fixable findings (see [Fixing findings](#fixing-findings)) |
| `vaso visualize` | Emit USecVisLib config files for visualization |
| `vaso update` | Fetch signed threat-feed updates (published at least monthly — see [SECURITY.md](SECURITY.md#threat-feed-updates)) |
| `vaso mcp scan` | Scan MCP server configurations |
| `vaso mcp list` | List discovered MCP servers |
| `vaso skill audit <path>` | Audit a skill directory before installing |
| `vaso ext list` | List loaded user plugins (drop-in `~/.vaso/plugins/*.js` or `*.mjs`) |
| `vaso ext info <name>` | Show a user plugin's details |
| `vaso rules list` | List loaded declarative rules (and untrusted project rules that were not loaded) |
| `vaso rules validate <file>` | Validate a rule file |
| `vaso rules init` | Write a starter rule file (`~/.vaso/rules/example.yaml`, or `--dir <path>`) |
| `vaso probe manifest` | Print the probe manifest (what a remote scan collects) |
| `vaso probe validate <path>` | Validate a probe snapshot file |

See [doc/user-guide.md](doc/user-guide.md) for full option reference.

## Supported Agents

**Autonomous frameworks**

- **OpenClaw** — `~/.openclaw` (also `~/.openclaw-<profile>`, `$OPENCLAW_HOME`, `$OPENCLAW_STATE_DIR`), and `~/.clawdbot` while no `~/.openclaw` config exists; `$include` files are followed
- **NanoClaw** — v2 git checkout (`<checkout>/.env`, `data/`, `groups/`) + `~/.config/nanoclaw/` (mount allowlist)
- **PicoClaw** — `~/.picoclaw/`
- **IronClaw** — `~/.ironclaw/` (TOML, gRPC gateway)
- **Nanobot** — `~/.nanobot/` (Discord/Slack bot framework)
- **ZeroClaw** — `~/.zeroclaw/` (Composio integration)
- **NemoClaw** — `~/.nemoclaw/` (NVIDIA NIM, GPU isolation)
- **Hermes** — `~/.hermes/` plus the administrator-managed `/etc/hermes/` (or `$HERMES_MANAGED_DIR`) (API-server gateway model)
- **Lyrie** — `~/.lyrie/` (Bun turborepo, Rust Shield Layer 1, 10-channel gateway)
- **Atomic Agent** — `~/.atomic-agent/` or `$ATOMIC_AGENT_STATE_DIR` (config.json + .env; local-first operator agent with approval ladder, MCP, skills, Telegram/Discord channels, HTTP service)

**Agent sandbox runtime**
- **NVIDIA OpenShell** — `~/.config/openshell/` (CLI gateways, `gateway.toml`, `gateway.env`), `~/.local/state/openshell/` (gateway database, keys, sandbox tokens), Homebrew/snap gateway configs; with the CLI installed, each sandbox's effective policy is read from the gateway (read-only)

**Interactive coding agents**

- **Claude Code** — `~/.claude/`, `~/.claude.json`, project-level `.claude/`
- **Codex** — `~/.codex/{config.toml,auth.json}`
- **OpenCode** — XDG paths (`$XDG_CONFIG_HOME/opencode/`, `$XDG_DATA_HOME/opencode/`)
- **Gemini CLI** — `~/.gemini/` (settings.json + OAuth credential files)
- **Qwen Code** — `~/.qwen/` (multi-provider auth: OpenAI / Anthropic / Gemini / Dashscope / Bailian)
- **GitHub Copilot CLI** — `~/.copilot/` + workspace `.mcp.json` + `.github/lsp.json`
- **Cursor CLI/IDE** — `~/.cursor/` (cli-config.json, mcp.json, permissions.json, sandbox.json, hooks.json) + IDE user settings
- **Windsurf / Devin Desktop** — `~/.codeium/windsurf/`, `~/.config/devin/`, editor user-data dirs (both generations)
- **Devin CLI** — `~/.config/devin/` (config.json, mcp_config.json) + `~/.local/share/devin/credentials.toml`
- **Abacus.AI CLI / AbacusAI Desktop** — `~/.abacusai/` (config.json, mcp.json, keystore.enc, desktop per-mode configs) + project `.abacusai/`; AbacusAI Desktop user data

**Agentic desktop apps**

- **Claude Desktop** — `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS), `%APPDATA%\Claude\claude_desktop_config.json` (Windows); MCPB extensions
- **ChatGPT Desktop** — `/Applications/ChatGPT.app` and `/Applications/ChatGPT (Classic).app` + `~/Library/Application Support/com.openai.chat/`; preferences plist (macOS only)
- **Meta Muse** — `/Applications/Muse.app` + `com.meta.endo` preferences (macOS; initial coverage)
- **Perplexity Comet** — `/Applications/Comet.app` + Chromium profile (extension inventory, session data)
- **Grok Bot** — `~/.grokbot/` (settings.json, local-exec daemon credential, standing approvals; `$SAND_DATA_ROOT`) + Electron user data (`~/.config/Grok Bot`, `~/Library/Application Support/Grok Bot`: sand-secrets.json, user-secrets.json); app at `/opt/Grok Bot` or `/Applications/Grok Bot.app`

**MCP servers** — Claude Desktop, Claude Code, Codex, Gemini CLI, Qwen Code, GitHub Copilot CLI, Cursor, Windsurf, Devin CLI, Abacus.AI, Atomic Agent, Nanobot, PicoClaw, Lyrie, VS Code, project-level configs

## Security Checks

368 checks organized into 19 categories:

| Category | IDs | Count | Description |
|----------|-----|-------|-------------|
| Configuration | CFG-001–024 | 24 | Gateway binding, API keys, TLS, permissions, sandbox, NemoClaw hardening |
| Skill Code | SKL-001–013 | 13 | AST data-flow, obfuscation, eval/exec, reverse shells, workspace symlink escape |
| IOC Matching | IOC-001–008 | 8 | C2 IPs, malicious domains, typosquatting, file hashes |
| Network | NET-001–005 | 5 | Gateway exposure, WebSocket origins, proxy bypass |
| Runtime | RUN-001–005 | 5 | LaunchAgents, cron, Docker socket, VS Code trojans |
| Policy | POL-001–005 | 5 | DM policy, tool policy, sandbox compliance |
| MCP Server | MCP-001–035 | 35 | Transport security, credential exposure, tool injection, toxic flows, rug pull, stdio shell-c, world-writable command paths, streamable-HTTP origin pinning, tool-description poisoning, cross-server tool-name collision, slash-command overlap, remote-server-without-auth, filesystem sensitive-path scope, vulnerable/rolled-back version, config drift, untrusted installer source, env-dump tool, long-lived token, hardcoded prompt-injection directives in tool output, obfuscated/encoded server source; opt-in npm package source resolution; OWASP MCP Top 10 coverage mapping |
| Advisory | ADV-001–005 | 5 | Vulnerability/CVE detection with version awareness |
| Coding Agent | CC, CD, CG, CDX, OPC, GEM, QC, CUR, GHC, WS, DEV, ABA, MM, PC, GB | 151 | Claude Code (12), Claude Desktop (10), ChatGPT Desktop (6), Codex (10), OpenCode (12), Gemini CLI (12), Qwen Code (10), Cursor (15), GitHub Copilot CLI (9), Windsurf/Devin Desktop (9), Devin CLI (10), Abacus.AI CLI/Desktop (15), Meta Muse (3), Perplexity Comet (2), Grok Bot (16) — sandbox/approval policy, plaintext credentials, MCP pinning, broad allow rules, memory-file secrets, transport security |
| Agent-Specific | OC, NC, PCL, IC, NB, ZC, LY, HM, AT | 103 | Per-framework checks (OpenClaw 7, NanoClaw 5, PicoClaw 7, IronClaw 14, Nanobot 12, ZeroClaw 16, Lyrie 20, Hermes 11, Atomic Agent 11) |
| OpenShell | OSH-001–014 | 14 | NVIDIA OpenShell gateway: TLS off, unauthenticated users, plaintext OIDC, non-expiring session credentials, fail-open policy validation and extensions, resource admission off, readable keys/tokens/credential database, writable config, CLI without TLS verification; sandbox policies: any-program network rules, uninspected/unenforced egress, broad address ranges, writable system paths |

Server-only checks (gateway/network/runtime concepts) are automatically excluded for coding agents to avoid false positives — interactive coding CLIs have a different threat model than autonomous server agents.

## Output Formats

```bash
vaso scan                              # Terminal (default) — color-coded with score
vaso scan --format json -o report.json # JSON — structured, machine-readable
vaso scan --format sarif -o results.sarif  # SARIF — GitHub Code Scanning compatible
vaso scan --format markdown -o report.md   # Markdown — for PR comments
vaso scan --format html -o report.html     # HTML — standalone report
vaso scan --format csv -o results.csv      # CSV — one row per check result/evidence item, for SIEM ingestion
vaso scan --format junit -o results.xml    # JUnit XML — for CI test-result reporters
```

Markdown, SARIF, and HTML reports also include **OWASP coverage mappings** — both the [OWASP MCP Top 10](https://owasp.org/) and the [OWASP Agentic AI Top 10](https://github.com/precize/Agentic-AI-Top10-Vulnerability) — showing which checks address each risk and flagging the risks a static scanner cannot cover (e.g. AAI014 Alignment Faking).

## Scoring

VASO produces a 0–100 score with a letter grade (A–F) per agent. Critical findings deduct 12 points, warnings deduct 5.

When multiple agents are detected, the **headline score is worst-case** — the lowest-scoring agent — because a security posture is gated by its weakest agent, and a mean would grow more reassuring as clean agents are added, hiding a critical exposure in a large fleet. The mean is still reported as a secondary **Fleet average** (`fleetAverage` in JSON output) for trend tracking.

## Fixing findings

`vaso fix` changes files on disk. Before applying anything:

- Run `vaso fix --dry-run` first to see what would change.
- Without `-y`, VASO asks before each fix (yes / no / all / quit). Without `-y` on a non-interactive terminal it exits 2.
- Every changed file is backed up first under `~/.vaso/backups/<timestamp>/`. `vaso fix --rollback` undoes the last fix run (run it again for the one before); `vaso fix --rollback <backup>` restores a named backup.
- Fixes only change regular files inside the home of the user the agent belongs to. Files outside that home, symlinks and hard-linked files are refused, and the finding says what to change by hand.
- Permission fixes remove group and other access; they never widen it.

## CI/CD Integration

### GitHub Action

The simplest path — drop one step into any workflow:

```yaml
- uses: vulnex/vaso@v1.4.3
  id: vaso
  with:
    fail-on: critical          # or warning, info, none
    format: sarif              # sarif, json, markdown, html, csv, junit, terminal
```

Inputs:

| Input | Default | Description |
|-------|---------|-------------|
| `version` | `v1.4.3` | VASO version to install. A release tag installs the prebuilt release tarball; a branch or commit SHA installs from the git ref |
| `agent` | (all detected) | Scan a single agent only (any `--agent` value) |
| `format` | `sarif` | `terminal`, `json`, `sarif`, `markdown`, `html`, `csv` or `junit` |
| `output` | `vaso-results.<ext>` | Path for the report (none for `terminal`) |
| `fail-on` | `critical` | Fail the step on findings of this severity or higher: `critical`, `warning`, `info` or `none` |
| `working-directory` | `.` | Directory to run `vaso` from |
| `upload-sarif` | `true` | With `format: sarif`, upload the report to GitHub Code Scanning |
| `debug` | `false` | Pass `--debug` (full stack traces on errors) |
| `extra-args` | (none) | Extra flags appended to `vaso scan`, split on whitespace |

Output: `report-path`, the absolute path of the report (`${{ steps.vaso.outputs.report-path }}`). It is set even when the step fails on findings, so the SARIF upload still runs. The step's exit code is VASO's (see [Exit codes](#exit-codes)).

### Manual workflow

```yaml
- name: Install VASO
  run: curl -fsSLo /tmp/vaso.tgz https://github.com/vulnex/vaso/releases/download/v1.4.3/vaso-1.4.3.tgz && npm install -g /tmp/vaso.tgz

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

## Declarative Rules

Custom rules are YAML files that add checks without writing code. Each rule has one type: `config` (compare a config value), `pattern` (regex over config or skill files) or `file_exists`. A rule may carry a `fix` that `vaso fix` applies.

`vaso scan` and `vaso fix` load rules from:

- `~/.vaso/rules/` — your own rules. Files (or the folder) that group or others can write are not loaded.
- `.vaso/rules/` in the current directory — a repository's rules. Loaded only with `--project-rules` or when the project's absolute path is listed in `~/.vaso/trusted-projects` (one per line; the file is ignored if group or others can write it). Their `fix.set` is never applied, and they can't replace a rule ID you already define.
- `--rules <paths...>` — extra rule files or folders.

`--no-custom-rules` skips them all. A rule whose ID matches a built-in check is skipped with a warning.

```yaml
# ~/.vaso/rules/org.yaml
rules:
  - id: ORG-001
    name: Debug mode enabled
    category: config
    severity: warning
    description: Debug mode must be off in production
    config:
      path: "server.debug"
      operator: "eq"
      value: true
```

```bash
vaso rules init                    # write a commented starter file to ~/.vaso/rules/example.yaml
vaso rules validate org.yaml       # check a rule file
vaso rules list                    # show the rules a scan would load
```

See [Custom rule reference](doc/user-guide.md#custom-rule-reference) in the user guide for every field and operator.

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

For environments without Node.js, `vaso-quick.sh` runs 5 critical checks against an **OpenClaw** install (gateway binding, API key exposure, file permissions, sandbox, auth bypass) with standard Unix tools. It does not cover other agents. It exits 1 when a check fails, 0 otherwise.

```bash
# Without installing anything
curl -fsSL https://raw.githubusercontent.com/vulnex/vaso/main/bin/vaso-quick.sh | bash

# From a release install (on PATH next to vaso) or a clone
vaso-quick
bash bin/vaso-quick.sh
```

## Plugin System

VASO supports user plugins in `~/.vaso/plugins/` (`.js` or `.mjs` files, or a folder with an `index.mjs`/`index.js`). Plugins can add custom checks, output formatters, and agent adapters. A plugin is code that runs as your user on every `vaso` command: only install plugins you trust. See [examples/plugins/README.md](examples/plugins/README.md) for the plugin API (`registerCheck`, `registerAdapter`, `registerReporter`) with working examples, and [doc/development-guide.md](doc/development-guide.md) for VASO's internals.

## Files VASO keeps

Local state lives under `~/.vaso/` and never leaves the machine:

| Path | Contents |
|------|----------|
| `baselines/` | Scan baselines for `--save-baseline` / `--diff` |
| `backups/<timestamp>/` | Copies of files before `vaso fix` changed them (used by `--rollback`) |
| `ioc/`, `advisory/` | Signed feeds fetched by `vaso update` |
| `probe/` | Downloaded `vaso-probe` binaries for remote scans |
| `mcp-state/`, `mcp-tool-baselines/` | MCP drift state: server versions and config fingerprints (MCP-027, MCP-028), tool definitions (MCP-020) |
| `mcp-pkg-cache/` | Packages downloaded by `vaso mcp scan --resolve-packages` |
| `plugins/` | User plugins |
| `rules/` | Your declarative rules |
| `trusted-projects` | Projects whose `.vaso/rules/` load without `--project-rules` |

## Documentation

- [User Guide](doc/user-guide.md) — full command reference and configuration ([Troubleshooting](doc/user-guide.md#troubleshooting))
- [Network Scanning Guide](doc/network-scanning-guide.md) — SSH, inventory, snapshot, and fleet workflows
- [Development Guide](doc/development-guide.md) — contributing and plugin development
- [Testing Guide](doc/testing-guide.md) — test suite and CI setup

## License

Apache-2.0 — see [LICENSE](LICENSE).
