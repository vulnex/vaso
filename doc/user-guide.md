# VASO User Guide

VASO (VULNEX Agent Security Observer) is a security scanner for AI agent deployments. It detects misconfigurations, malicious skills, known threats, and runtime vulnerabilities across ten autonomous agent frameworks (OpenClaw, NanoClaw, PicoClaw, IronClaw, Nanobot, ZeroClaw, NemoClaw, Hermes, Lyrie, Atomic Agent), the NVIDIA OpenShell agent sandbox runtime, ten interactive coding agents (Claude Code, Codex, OpenCode, Gemini CLI, Qwen Code, GitHub Copilot CLI, Cursor CLI/IDE, Windsurf/Devin Desktop, Devin CLI, Abacus.AI CLI/Desktop), four agentic desktop apps (Claude Desktop, ChatGPT Desktop, Meta Muse, Perplexity Comet), and MCP (Model Context Protocol) server configurations.

## Installation

VASO is distributed from GitHub. The npm name `vaso` is held by an unrelated package; do not install that.

```bash
# One-liner (Linux / macOS / WSL) — recommended
curl -fsSL https://raw.githubusercontent.com/vulnex/vaso/main/install.sh | bash

# Or install the prebuilt release tarball directly with npm
npm install -g https://github.com/vulnex/vaso/releases/download/v1.2.1/vaso-1.2.1.tgz
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
| `-a, --agent <type>` | Scan a specific agent: `openclaw`, `nanoclaw`, `picoclaw`, `ironclaw`, `nanobot`, `zeroclaw`, `nemoclaw`, `openshell`, `hermes`, `lyrie`, `atomic-agent`, `claude-code`, `claude-desktop`, `chatgpt-desktop`, `codex`, `opencode`, `gemini-cli`, `qwen-code`, `copilot-cli`, `cursor-cli`, `windsurf`, `devin`, `abacus`, `meta-muse`, or `comet` |
| `-f, --format <format>` | Output format: `terminal` (default), `json`, `sarif`, `markdown`, `html`, `csv`, `junit` |
| `-o, --output <file>` | Write report to a single file instead of stdout |
| `--output-dir <dir>` | Write one file per host as `<dir>/<hostname>.<ext>`; local scans use the local hostname (mutually exclusive with `-o`). A second target reporting the same hostname (two users on one machine, cloned VMs) is written as `<hostname>--<user@host>.<ext>`; `--save-snapshot` files are named the same way |
| `--save-baseline` | Save current results as a baseline for future comparison |
| `--diff` | Compare results against the last saved baseline |
| `--all-users` | Scan all user accounts (requires root/sudo) |
| `--fail-on <severity>` | Exit non-zero on findings of this severity or higher: `critical` (default), `warning`, `info`, or `none` |
| `--silent` | Suppress all stdout/stderr chatter; requires `-o` or `--output-dir` |
| `--no-color` | Disable colored terminal output |
| `--host <target...>` | Scan one or more remote hosts via SSH (`user@host[:port]`). Variadic. |
| `--inventory <path>` | YAML file listing hosts to scan |
| `--ssh-key <path>` | SSH identity file for remote connections |
| `--ssh-timeout <seconds>` | Per-attempt SSH connection timeout (default 60); uploading and running the probe may take up to 10 minutes |
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

An inventory is a YAML list of hosts. `host` takes a hostname or `user@host[:port]` (as `--host` does); `user` defaults to `root`, `port` to 22:

```yaml
hosts:
  - host: deploy@10.0.1.5        # user@host, like --host
  - host: 10.0.1.6
    user: ops
    port: 2222
    label: prod-agent-02         # name shown in progress output and reports
    identity: ~/.ssh/id_prod     # per-host key (default: --ssh-key)
    sudo: true                   # run the probe with sudo (multi-user scans)
```

Any other key is an error (exit 2) — a misspelt `identity` would otherwise be ignored and the scan would use a different key.

### `vaso detect`

Lists installed AI agents without running any security checks. Useful for verifying which agents VASO can see before running a full scan.

The reported version is that of the CLI your `PATH` resolves. Other copies of the same agent at different versions (an older npm global, a copy under another nvm/fnm/asdf/mise Node version, or a past version a self-updating installer keeps on disk) are listed as **Other copies**, and the advisory checks (ADV-001/003/004) evaluate each of them, so a vulnerable leftover is flagged even when the copy you run is current.

```
vaso detect [options]
```

| Option | Description |
|--------|-------------|
| `-a, --agent <type>` | Detect a specific agent only: `openclaw`, `nanoclaw`, `picoclaw`, `ironclaw`, `nanobot`, `zeroclaw`, `nemoclaw`, `openshell`, `hermes`, `lyrie`, `atomic-agent`, `claude-code`, `claude-desktop`, `chatgpt-desktop`, `codex`, `opencode`, `gemini-cli`, `qwen-code`, `copilot-cli`, `cursor-cli`, `windsurf`, `devin`, `abacus`, `meta-muse`, or `comet` |
| `-f, --format <format>` | Output format: `terminal` (default) or `json` |
| `-o, --output <file>` | Write report to a file instead of stdout |
| `--output-dir <dir>` | Multi-host: write one file per host as `<dir>/<hostname>.<ext>` (mutually exclusive with `-o`) |
| `--all-users` | Detect across all user accounts (requires root/sudo) |
| `--verbose` | Show the search paths checked for each adapter |
| `--silent` | Suppress all stdout/stderr chatter; requires `-o` or `--output-dir` |
| `--host <target...>` | Detect on one or more remote hosts via SSH (`user@host[:port]`). Variadic. |
| `--inventory <path>` | YAML file listing hosts to detect against |
| `--ssh-key <path>` | SSH identity file for remote connections |
| `--ssh-timeout <seconds>` | Per-attempt SSH connection timeout (default 60); uploading and running the probe may take up to 10 minutes |
| `--ssh-retries <n>` | Additional SSH attempts after the first failure (default 0) |
| `--parallel <n>` | Max hosts to detect concurrently (default 5) |
| `--snapshot <path>` | Detect from a pre-collected probe snapshot file |
| `--save-snapshot <dir>` | When detecting over SSH, write each host's snapshot to `<dir>/<hostname>.json` |
| `--no-color` | Disable colored terminal output |

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
| `--fail-on <severity>` | Exit 1 on findings of this severity or higher: `critical` (default), `warning`, `info`, `none` |
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

Exit code 1 is returned if any finding at or above `--fail-on` (default `critical`) is detected. If the path does not exist or is not a directory, VASO exits with code 2 without scanning; only an empty directory is reported as having nothing to audit (exit 0) — documentation, `package.json` and config files are audited too (SKL-007, IOC checks). Skills symlinked in from elsewhere are followed and scanned.

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
| `--rollback [backup]` | Undo the last fix run; run it again to undo the one before. Name a backup (from `~/.vaso/backups/`, owner-only) to restore that one |

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
| `-i, --input <file>` | Use an existing scan-result JSON instead of running a fresh scan. A `--host`/`--inventory` JSON report works too: one host is written to the output directory, several hosts to one subdirectory each (hosts that were not scanned are skipped) |
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

Fetch the IOC (Indicators of Compromise) and advisory threat-intelligence feeds. Both feeds are signed with a pinned Ed25519 key (`src/ioc/public-key.ts`) and rejected on version rollback — see `SECURITY.md`. Verified feeds are cached under `~/.vaso/ioc/` and `~/.vaso/advisory/` (feed, signature, and `metadata.json`) and loaded on top of the bundled databases, which remain the offline baseline.

Feeds are published **at least monthly**, with out-of-band publishes for actively exploited issues — see the "Threat Feed Updates" section of `SECURITY.md` for the full policy.

```bash
vaso update           # Fetch latest signed feeds
vaso update --force   # Update even if feeds are not stale
vaso update --url <url>  # Custom feed URL (must still be signed with the pinned key)
```

### `vaso mcp scan`

Scan MCP (Model Context Protocol) server configurations for security issues. This auto-discovers MCP configs from Claude Desktop, Claude Code, Gemini CLI, Qwen Code, Codex, GitHub Copilot CLI, Cursor, Windsurf, Devin CLI, Abacus.AI, Atomic Agent, Nanobot, PicoClaw, Lyrie, VS Code (user and project `mcp.json`), and project-level config files. `CLAUDE_CONFIG_DIR`, `CODEX_HOME`, `COPILOT_HOME` and `GEMINI_CLI_HOME` relocations are followed.

```
vaso mcp scan [options]
```

| Option | Description |
|--------|-------------|
| `-f, --format <format>` | Output format: `terminal` (default), `json`, `sarif`, `markdown`, `html`, `csv`, `junit` |
| `-o, --output <file>` | Write report to a file instead of stdout |
| `-p, --path <paths...>` | Specific config file paths to scan (skips auto-discovery). A path that is missing or not valid JSON/JSONC is an error (exit 2) |
| `--resolve-packages` | Download npm-packaged (`npx`) MCP servers — download only, never executed — and analyze their source. Requires network access |
| `--audit-deps` | Look up the exact versions of the servers' dependencies (from their lockfiles or installed copies) in [OSV.dev](https://osv.dev) for known vulnerabilities, in addition to the bundled advisories. Sends package names and versions only — never code, paths or config. Dependencies known only by a declared range are not looked up. If OSV can't be reached the scan continues with bundled advisories. Requires network access |
| `--fail-on <severity>` | Exit 1 on findings of this severity or higher: `critical` (default), `warning`, `info`, `none` |
| `--source <paths...>` | Analyze MCP server source directly — an entry file, a server checkout, or a Python package checkout (`pyproject.toml` + `src/<pkg>/`, all of its modules). For server authors, and for remote servers whose code you have but only connect to (`npx mcp-remote https://…`). On its own it scans only these servers (no config discovery); with `-p`, both. A path with no server source is an error (exit 2) |
| `--no-color` | Disable colored terminal output |

Examples:

```bash
# Scan all auto-discovered MCP configs
vaso mcp scan

# Scan a specific config file
vaso mcp scan --path ~/.claude/mcp.json

# Generate JSON report
vaso mcp scan --format json -o mcp-report.json

# Also fetch and analyze the source of npx-launched servers
vaso mcp scan --resolve-packages

# Audit a server's own code (a checkout or its entry file) — e.g. before publishing it
vaso mcp scan --source ./my-mcp-server

# Also check every dependency version the servers ship against OSV.dev
vaso mcp scan --audit-deps
```

Servers run from local files are analyzed whether they are JavaScript/TypeScript (`node server.js`) or Python (`python3 server.py`, a virtualenv interpreter, `uv run server.py`). Text files a server names in its code and reads at runtime (a `documents/` folder it returns to the model) are checked for injected instructions too. Remote servers reached through a local bridge (`npx mcp-remote <url>`, `npx supergateway --sse <url>`) get the same transport and authentication checks as `url` entries.

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
| `1` | Findings at or above the threshold |
| `2` | VASO could not run: invalid CLI arguments (e.g. `--silent` without an output destination, `--parallel 0`), an unreadable snapshot or inventory file, or an internal error |
| `3` | Scan incomplete: one or more remote hosts could not be scanned (unreachable, authentication failed, probe error). Takes precedence over `1`, so CI can tell "not scanned" apart from "findings" |

The other commands use the same codes: `skill audit` and `mcp scan` exit `1` on critical findings, and every command exits `2` when it cannot run — a command-line error (unknown option or command, a missing or extra argument), a missing or unreadable input (`skill audit <path>`, `mcp scan/list --path`, `visualize -i`, `probe validate`), an unknown name (`ext info`), or an invalid option value such as `--ssh-timeout abc`. `probe validate` exits `1` when the snapshot is readable JSON but fails validation.

`--fail-on` accepts `critical` (default), `warning`, `info`, or `none`. Use `--fail-on none` to never fail on findings — useful for scans that only produce reports.

```bash
vaso scan --fail-on critical    # Default — only critical findings fail CI
vaso scan --fail-on warning     # Warning or critical fails CI
vaso scan --fail-on none        # Exit 0 unless VASO errors (2) or a host is unreachable (3)
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

VASO runs **347 checks across 19 categories**.

| Category | IDs | Count | Scope |
|----------|-----|-------|-------|
| Configuration | CFG-001–024 | 24 | Gateway binding, API keys, TLS, permissions, sandbox, NemoClaw hardening |
| Skill Code | SKL-001–013 | 13 | AST data-flow, obfuscation, eval/exec, reverse shells, workspace symlink escape |
| IOC Matching | IOC-001–008 | 8 | C2 IPs, malicious domains, typosquatting, file hashes |
| Network | NET-001–005 | 5 | Gateway exposure, WebSocket origins, proxy bypass |
| Runtime | RUN-001–005 | 5 | LaunchAgents, cron, Docker socket, VS Code trojans |
| Policy | POL-001–005 | 5 | DM policy, tool policy, sandbox compliance |
| MCP Server | MCP-001–035 | 35 | Transport security, credentials, tool injection, toxic flows, rug pull, OAuth 2.1, stdio shell-c, world-writable command paths, streamable-HTTP origin pinning, tool-description poisoning, cross-server tool-name collision, slash-command overlap, remote-server-without-auth, filesystem sensitive-path scope, vulnerable/rolled-back version, config drift, untrusted installer source, env-dump tool, long-lived token, prompt-injection directives in tool output, obfuscated/encoded server source (with what it hides), lookalike/typosquatted server names, credentials hardcoded in server source, servers listening on all interfaces without authentication, disabled Host/Origin (DNS-rebinding) protection; known-vulnerable MCP SDK and library versions a server ships with (from its lockfile, installed copy or manifest), deprecated packages, opt-in OSV.dev lookup (`--audit-deps`); tools that read, write or list any path the caller names; fetched pages and files returned unfiltered as tool results (higher when the caller picks the URL or anyone can publish on the host); JavaScript and Python server source; remotes behind `mcp-remote`/`supergateway`; opt-in npm package source resolution (`--resolve-packages`); direct source audit (`--source`); OWASP MCP Top 10 mapping |
| Advisory | ADV-001–005 | 5 | Vulnerability/CVE detection with version awareness |
| OpenClaw | OC-* | 6 | Sub-agent config downgrade, legacy bot dirs, `OPENCLAW_HOME` redirect, profile downgrade, memory file perms, `/etc/openclaw` writable |
| NanoClaw | NC-001–005 | 5 | Overbroad mount allowlist (`allowedRoots`), host config/credential exposure, checkout/state exposure, webhook listener on all interfaces, skills dirs writable |
| PicoClaw | PCL-001–007 | 7 | Workspace restriction off, exec deny list disabled or bypassed, channels open to any sender (empty `allow_from` allows everyone), exec reachable from chat channels, weakly guarded `pico` WebSocket, public web launcher without a dashboard password, tool path allowances reaching credentials |
| IronClaw | IC-001–014 | 14 | 1.x (Reborn) and 0.x: WebUI/listener bind, cleartext LLM endpoints, WebUI token and master-key exposure, `local-dev-yolo` host access, approval policy, sandbox (0.x), permissive WebUI CORS, world-readable state DB |
| Nanobot | NB-001–012 | 12 | Open channels (`allowFrom: ["*"]`, open DM policy), plaintext secrets, workspace restriction, exec sandbox/allow patterns, SSRF whitelist, writable prompt/memory/cron files, unauthenticated WebUI, readable chat history, API server exposure, unpinned MCP packages |
| ZeroClaw | ZC-001–016 | 16 | V3 schema: plaintext/XOR secrets, gateway bind and pairing, `full` risk level, filesystem scope, open peer groups, open skills/scripts, WhatsApp session perms, browser/HTTP private-host access, sandbox, unrestricted commands/auto-approve, relaxed gateway safeguards |
| Lyrie | LY-001–020 | 20 | Checkout `.env` + `~/.lyrie` state: Shield mode/binary, channel DM policy, secrets-file perms, WebChat exposure/origins, pairing and edit ledgers, local-mode leaks, `NODE_ENV=development` SSRF gap, broad `LYRIE_FS_ROOT`, readable memory DB |
| Hermes | HM-001–010 | 10 | Plaintext API keys, env/credentials perms, API-server bind without auth, permissive CORS, plaintext inference endpoints, approvals-off, Tirith pre-exec scanner state, MCP stdio shell-c / unpinned packages |
| OpenShell | OSH-001–014 | 14 | Gateway TLS disabled, unauthenticated users, OIDC over plaintext HTTP, non-expiring SSH/sandbox credentials, `retain_last_valid` policy validation, fail-open or plaintext interceptors/middleware, resource admission off (critical with caller driver config), readable CA/JWT/TLS keys, key-encryption key, credential database and sandbox tokens, writable gateway config or CLI gateway metadata, CLI without TLS verification; live sandbox policies: network rules open to any program (`/**`), `tls: skip` / uninspected credentials / allow-all MCP / no protocol / `access: full` / audit-only rules, `allowed_ips` of /8 or wider and `host.openshell.internal`, writable system paths |
| Atomic Agent | AT-001–011 | 11 | Raised approval ladder (level 4/5), unrestricted read scope, unapproved HTTP egress, plaintext secrets in config.json, `.env`/mail-session perms, `pure_read` MCP trust, MCP stdio/transport hygiene, secretless webhooks, subscription-CLI lockdown overrides, plaintext inference endpoints, world/group-readable memory, sessions and traces |
| Coding Agent | CC, CD, CG, CDX, OPC, GEM, QC, CUR, GHC, WS, DEV, ABA, MM, PC | 132 | Claude Code (12), Claude Desktop (10), ChatGPT Desktop (6), Codex (10), OpenCode (12), Gemini CLI (11), Qwen Code (10), Cursor (14), GitHub Copilot CLI (9), Windsurf/Devin Desktop (8), Devin CLI (10), Abacus.AI CLI/Desktop (15), Meta Muse (3), Perplexity Comet (2): sandbox/approval policy, plaintext credentials, MCP pinning, broad allow rules, memory-file secrets, transport security |

Server-only checks (gateway/network/runtime concepts, mostly in CFG, NET, RUN, and POL) are automatically excluded for coding agents and desktop apps to avoid false positives — interactive coding CLIs have a different threat model than autonomous server agents.

## Supported Agents

VASO ships twenty-five adapters. Each implements `detect()`, `getConfigPaths()`, `getSkillsDir()`, and `getGatewayInfo()` against its framework's on-disk layout.

### Autonomous frameworks

| Adapter | Config locations | Formats |
|---------|------------------|---------|
| OpenClaw | `$OPENCLAW_HOME`, `~/.openclaw`, `~/.clawdbot`, `~/.moltbot`, `/etc/openclaw` | JSON, YAML, ENV |
| NanoClaw | v2 git checkout (`package.json`, `.env`; found via its service unit or common locations), `~/.config/nanoclaw/mount-allowlist.json` | JSON, ENV |
| PicoClaw | `$PICOCLAW_HOME` (default `~/.picoclaw`): `config.json`, `.security.yml`, `auth.json`, `launcher-config.json`; skills in `workspace/skills` | JSON, YAML |
| IronClaw | 1.x: `$IRONCLAW_REBORN_HOME` (default `~/.ironclaw/reborn/`); 0.x: `~/.ironclaw/` | TOML, JSON, ENV |
| Nanobot | `~/.nanobot/config.json` + workspace (`agents.defaults.workspace`) | JSON |
| ZeroClaw | `$ZEROCLAW_CONFIG_DIR` (default `~/.zeroclaw/`): `config.toml` (V3), `auth-profiles.json` | TOML, JSON |
| NemoClaw | `~/.nemoclaw/`, `/etc/nemoclaw/` | JSON, YAML |
| Hermes | `~/.hermes/`, `/etc/hermes/` | YAML, ENV |
| Lyrie | git checkout `.env` (found via its service unit or common locations, `package.json` name `lyrie-agent`) + `~/.lyrie/` state (`config.json`, `mcp.json`, pairing/edit ledgers, memory) | ENV, JSON |
| Atomic Agent | `~/.atomic-agent/` or `$ATOMIC_AGENT_STATE_DIR` (config.json, .env, skills/; MCP servers also discovered by `vaso mcp`) | JSON, ENV |

### Agent sandbox runtime

| Adapter | Config locations | Formats |
|---------|------------------|---------|
| NVIDIA OpenShell | `$XDG_CONFIG_HOME/openshell/` (`gateway.toml`, `gateway.env` — which can redirect the TOML, database and TLS dir, as NemoClaw does — `active_gateway`, `gateways/<name>/`), `$XDG_STATE_HOME/openshell/` (gateway database, key-encryption key, TLS, sandbox tokens), Homebrew `<prefix>/var/openshell/`, snap `/var/snap/openshell/common/`. With the `openshell` CLI installed, VASO reads each sandbox's effective policy and the global policy from the user's active gateway with read-only queries (`sandbox list`, `policy get`); `$OPENSHELL_SANDBOX_POLICY` is read too. Remote scans run the same queries through the probe. NemoClaw installs report their gateway here | TOML, ENV, JSON, YAML |

### Interactive coding agents

| Adapter | Config locations | Formats |
|---------|------------------|---------|
| Claude Code | `~/.claude/`, `~/.claude.json`, project `.claude/` | JSON |
| Codex | `~/.codex/config.toml`, `~/.codex/auth.json` | TOML, JSON |
| OpenCode | `$XDG_CONFIG_HOME/opencode/opencode.json[c]`, `$XDG_DATA_HOME/opencode/auth.json` | JSON, JSONC |
| Gemini CLI | `~/.gemini/settings.json`, OAuth credential files (`oauth_creds.json`, `google_accounts.json`, `mcp-oauth-tokens.json`); project `.gemini/` | JSONC |
| Qwen Code | `~/.qwen/settings.json` (multi-provider auth: OpenAI/Anthropic/Gemini/Dashscope/Bailian); project `.qwen/` | JSONC |
| GitHub Copilot CLI | `~/.copilot/config.json`, `settings.json`, `command-history-state.json`, `session-state/`; workspace `.mcp.json` + `.github/lsp.json` | JSONC |
| Cursor CLI/IDE | `~/.cursor/` (`cli-config.json`, `mcp.json`, `permissions.json`, `sandbox.json`, `hooks.json`); project `.cursor/`; IDE user-data dir (`~/Library/Application Support/Cursor/`, `~/.config/Cursor/`, `%APPDATA%\Cursor\`: `User/settings.json`, `User/globalStorage/state.vscdb`); IDE-only installs via `/Applications/Cursor.app` | JSON |
| Windsurf / Devin Desktop | `~/.codeium/windsurf/` (`mcp_config.json`, memories, workflows, `user_settings.pb`), `~/.config/devin/mcp_config.json`; editor user-data `{Windsurf,Devin}` dirs (`~/Library/Application Support/`, `~/.config/`, `%APPDATA%`); version from the app's `product.json` | JSON |
| Devin CLI | `$XDG_CONFIG_HOME/devin/` (default `~/.config/devin/`: `config.json`, `mcp_config.json`, `AGENTS.md`), `$XDG_DATA_HOME/devin/credentials.toml`; project `.devin/` (found by walking up to the repo root) incl. `hooks.v1.json`; `%APPDATA%\devin\` on Windows | JSONC, TOML |
| Abacus.AI CLI / AbacusAI Desktop | `~/.abacusai/` (`config.json`, `mcp.json`, `trusted-workspaces.json`, `keystore.enc`, `desktop/mcp-<mode>.json`, `desktop/agent-config-<mode>.json`), project `<workspace>/.abacusai/` (ignored until the workspace is trusted); AbacusAI Desktop user data (`~/.config/AbacusAI Desktop`, `~/Library/Application Support/AbacusAI Desktop`); CLI copies: `~/.abacusai/bin`, npm `@abacus-ai/cli`, `~/.abacusai/versions/`, the desktop app's bundled CLI | JSON |

### Agentic desktop apps

| Adapter | Config locations | Formats |
|---------|------------------|---------|
| Claude Desktop | `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS), `%APPDATA%\Claude\claude_desktop_config.json` (Windows); MCPB extensions under `Claude Extensions/` | JSON |
| ChatGPT Desktop | `/Applications/ChatGPT.app` (current app, `com.openai.codex`) and `/Applications/ChatGPT (Classic).app` (`com.openai.chat`) + `~/Library/Application Support/com.openai.chat/`; preferences in `~/Library/Preferences/com.openai.chat*.plist` (macOS only) | plist |
| Meta Muse | `/Applications/Muse.app`, `~/Library/Preferences/com.meta.endo.plist`, `~/Library/Application Support/com.meta.endo/` (macOS only; initial coverage) | plist |
| Perplexity Comet | `/Applications/Comet.app` + Chromium profile `~/Library/Application Support/Comet/` (macOS) or `%LOCALAPPDATA%\Perplexity\Comet\User Data` (Windows): session-data permissions, extension inventory | — |

### MCP Servers

VASO auto-discovers MCP server configurations from multiple sources:

**Global configs:**
- `~/Library/Application Support/Claude/claude_desktop_config.json` (Claude Desktop, macOS)
- `~/.config/Claude/claude_desktop_config.json` (Claude Desktop, Linux)
- `%APPDATA%\Claude\claude_desktop_config.json` (Claude Desktop, Windows)
- `~/.claude.json` (Claude Code: user-scope `mcpServers` and each project's local-scope `projects.<path>.mcpServers`, as written by `claude mcp add`) and `~/.claude/mcp.json`
- `~/.gemini/settings.json` (Gemini CLI `mcpServers`; `httpUrl` is streamable HTTP, `url` is SSE)
- `~/.qwen/settings.json` (Qwen Code `mcpServers`)
- `$CODEX_HOME/config.toml` (Codex `[mcp_servers.<name>]`; default `~/.codex/`)
- `~/.cursor/mcp.json` (Cursor)
- `~/.codeium/windsurf/mcp_config.json` (Windsurf)
- `$XDG_CONFIG_HOME/devin/mcp_config.json` (Devin CLI / Devin Desktop; default `~/.config/devin/`, `%APPDATA%\devin\` on Windows)
- `~/.abacusai/mcp.json`, `~/.abacusai/config.json` (array form) and `~/.abacusai/desktop/mcp-<mode>.json` (Abacus.AI CLI / AbacusAI Desktop; servers marked `disabled` are skipped)
- `~/.atomic-agent/config.json` or `$ATOMIC_AGENT_STATE_DIR/config.json` (Atomic Agent `mcp.servers[]`)
- `~/.nanobot/config.json` (Nanobot)
- `$PICOCLAW_CONFIG` or `$PICOCLAW_HOME/config.json` (PicoClaw; default `~/.picoclaw/config.json`)
- `~/.lyrie/mcp.json` (Lyrie)

**Project-level configs:**
- `.mcp.json` (Claude Code project)
- `.cursor/mcp.json` (Cursor project)
- `.windsurf/mcp.json` (Windsurf project)
- `.devin/mcp_config.json`, `.devin/mcp_config.local.json` (Devin CLI project)
- `.abacusai/mcp.json`, `.abacusai/config.json` (Abacus.AI project)
- `.vscode/mcp.json` (VS Code)
- `mcp.json` (Generic MCP)

JSON files may be JSONC (comments, trailing commas) and may start with a UTF-8 byte-order mark. You can also point VASO at specific config files with `vaso mcp scan --path <file>`; a `.toml` path is read as a Codex config.

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

One row per finding, designed for SIEM / data-warehouse ingestion. Columns: `timestamp`, `agent`, `agent_name`, `check_id`, `check_name`, `category`, `severity`, `passed`, `message`, `file`, `line`, `snippet`, `detail`.

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
        run: npm install -g https://github.com/vulnex/vaso/releases/download/v1.2.1/vaso-1.2.1.tgz

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
| `~/.vaso/ioc/` | IOC feed cache + metadata fetched by `vaso update` |
| `~/.vaso/advisory/` | Advisory/CVE feed cache + metadata fetched by `vaso update` |
| `~/.vaso/probe/` | Downloaded `vaso-probe` binaries for remote scanning |

Nothing under `~/.vaso/` leaves the machine. VASO makes outbound network calls only in these cases:

- `vaso update` — fetches the signed IOC/advisory feeds
- `vaso mcp scan --resolve-packages` (opt-in) — downloads npm package tarballs for source analysis; they are never executed
- `vaso mcp scan --audit-deps` (opt-in) — sends the names and exact versions of MCP servers' dependencies to OSV.dev (no code, paths or config)
- `--host` / `--inventory` remote scans — connect over SSH and, on first use, download the `vaso-probe` binary from GitHub Releases (SHA-256-verified, cached under `~/.vaso/probe/`)
- IOC-008 (opt-in) — queries VirusTotal with skill-file hashes only when `VIRUSTOTAL_API_KEY` is set

## Safety Guarantees

- VASO never executes scanned code (all analysis is purely static)
- No data leaves the machine unless you explicitly pipe output elsewhere
- Remediation always creates backups before modifying files
- The scanner runs read-only by default; only `vaso fix` modifies files
