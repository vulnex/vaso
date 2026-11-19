# VASO User Guide

VASO (VULNEX Agent Security Observer) is a security scanner for AI agent deployments. It detects misconfigurations, malicious skills, known threats, and runtime vulnerabilities across ten autonomous agent frameworks (OpenClaw, NanoClaw, PicoClaw, IronClaw, Nanobot, ZeroClaw, NemoClaw, Hermes, Lyrie, Atomic Agent), the NVIDIA OpenShell agent sandbox runtime, ten interactive coding agents (Claude Code, Codex, OpenCode, Gemini CLI, Qwen Code, GitHub Copilot CLI, Cursor CLI/IDE, Windsurf/Devin Desktop, Devin CLI, Abacus.AI CLI/Desktop), five agentic desktop apps (Claude Desktop, ChatGPT Desktop, Meta Muse, Perplexity Comet, Grok Bot), and MCP (Model Context Protocol) server configurations.

## Installation

VASO is distributed from GitHub. The npm name `vaso` is held by an unrelated package; do not install that.

```bash
# One-liner (Linux / macOS / WSL) — recommended
curl -fsSL https://raw.githubusercontent.com/vulnex/vaso/main/install.sh | bash

# Or download the prebuilt release tarball and install it with npm
curl -fLO https://github.com/vulnex/vaso/releases/download/v1.4.1/vaso-1.4.1.tgz && npm install -g ./vaso-1.4.1.tgz
```

Requirements: Node.js 20 or later.

Install the release **tarball**, not `npm install -g github:vulnex/vaso#<tag>` — on npm 11+ the global git-dependency install path mishandles the package and leaves an unusable install. Download the tarball first rather than passing its URL to npm: npm 12 refuses tarball URLs by default (`allow-remote=none`). The tarball is prebuilt and installs with no build step. To remove VASO, see [Uninstall](#uninstall).

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
| `-a, --agent <type>` | Scan a specific agent: `openclaw`, `nanoclaw`, `picoclaw`, `ironclaw`, `nanobot`, `zeroclaw`, `nemoclaw`, `openshell`, `hermes`, `lyrie`, `atomic-agent`, `claude-code`, `claude-desktop`, `chatgpt-desktop`, `codex`, `opencode`, `gemini-cli`, `qwen-code`, `copilot-cli`, `cursor-cli`, `windsurf`, `devin`, `abacus`, `meta-muse`, `comet`, or `grok-bot` |
| `-f, --format <format>` | Output format: `terminal` (default), `json`, `sarif`, `markdown`, `html`, `csv`, `junit` |
| `-o, --output <file>` | Write report to a single file instead of stdout |
| `--output-dir <dir>` | Write one file per host as `<dir>/<hostname>.<ext>`; local scans use the local hostname (mutually exclusive with `-o`). A second target reporting the same hostname (two users on one machine, cloned VMs) is written as `<hostname>--<user@host>.<ext>`; `--save-snapshot` files are named the same way |
| `--save-baseline` | Save current results as a baseline for future comparison |
| `--diff` | Compare results against the last saved baseline |
| `--all-users` | Scan all user accounts (requires root/sudo) |
| `--fail-on <severity>` | Exit non-zero on findings of this severity or higher: `critical` (default), `warning`, `info`, or `none` |
| `--silent` | Suppress all stdout/stderr chatter; requires `-o` or `--output-dir` |
| `--no-color` | Disable colored terminal output |
| `--rules <paths...>` | Load additional declarative rule files or directories (see [Custom rule reference](#custom-rule-reference)); a file that can't be read, or whose rules don't validate, exits `2` |
| `--no-custom-rules` | Skip declarative rules (`~/.vaso/rules/`, `.vaso/rules/` and `--rules`) |
| `--project-rules` | Also load the working directory's `.vaso/rules/` (a repository's own rules; not loaded unless the project is trusted — see [Custom rule reference](#custom-rule-reference)) |
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

The SSH options (`--ssh-key`, `--sudo`, `--ssh-timeout`, `--ssh-retries`, `--parallel`) are accepted on local and `--snapshot` scans and ignored (with `--debug`, a note says so), so a wrapper can pass the same flags to every run. Their values are still checked: `--parallel 0` or `--ssh-timeout abc` exits `2` on any scan. `--save-snapshot` without `--host`/`--inventory`, and `--snapshot` together with `--host`/`--inventory`, are usage errors (exit `2`).

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

**What a remote scan can't see.** The probe collects the files and command output VASO's adapters name in advance, so a remote (or `--snapshot`) scan reaches the same verdicts as a local one except where a config points somewhere only known at scan time. Those cases are reported, never judged silently — scan the host locally to check them:

- **OpenClaw `$include` files** outside what the probe collects: it collects the `*.json5` files under the config directory (`~/.openclaw`, `~/.clawdbot`, `~/.openclaw-<profile>`). An include with another extension (`./gateway.json`), or one under an `OPENCLAW_INCLUDE_ROOTS` root outside the config directory, is reported as `CONFIG-LOAD` "not collected by the remote probe".
- **An OpenShell gateway TOML redirected** by `OPENSHELL_GATEWAY_CONFIG` in `gateway.env` to a location other than the defaults and NemoClaw's layout (`CONFIG-LOAD`).
- **Environment variables**: the probe ships only the variables adapters read (for example `HERMES_*`, `TIRITH_ENABLED`), with credential values redacted. A Hermes `config.yaml` `${VAR}` reference resolves from `~/.hermes/.env` on both, but one only the shell environment defines resolves only on a local scan.
- **Secrets in collected config files** never leave the host (probe ≥ 1.4.0). In `.env` files, settings JSON/YAML/TOML, instruction files and MCP configs, the probe replaces every API key, token or password it finds (known key formats, values under credential-named keys and `--token`-style arguments, URL passwords and `?api_key=` parameters, private-key bodies) with a stand-in of the same length and shape: the first 8 and last 4 characters stay, the rest is random. Checks reach the same verdict on it, and reports show the same masked value as a local scan. Placeholders (`sk-...`, `your-api-key`), references (`${OPENAI_API_KEY}`, `op://…`) and weak defaults (`changeme`) are kept as they are — they are what the checks report. Skill code, markdown and lockfiles are collected unchanged (IOC checks hash them); a skill's own settings and env files (`.env`, `config.json`, `secrets.yaml`, `.npmrc`, …) are disguised like agent configs.
- Conversation and history stores (Codex sessions, ChatGPT conversations, Gemini chats, Copilot history, editor `state.vscdb`) and token stores are collected for their permissions only, never their content; a Grok Bot `.deb` that has never run is versioned from its package metadata on local scans only.

**Skill directories outside the defaults.** A skills directory an agent's config sets (an OpenClaw `extraDirs` entry, a Nanobot, PicoClaw or ZeroClaw workspace), or an agent's own skills directory that a symlink takes elsewhere, is walked wherever it leads — locally and remotely, by the same rule — except in these places, judged on the path as written and as resolved:

- the filesystem root;
- your home directory itself, or any directory above it;
- another user's home (`/home/<user>`, `/Users/<user>`, `/root`; not `/Users/Shared`);
- OS directories (`/etc`, `/usr`, `/var`, `/bin`, `/sbin`, `/lib*`, `/System`, `/Library`, `/dev`, `/proc`, `/sys`, `/boot`, `/run`); `/opt`, `/srv`, `/nix`, `/Volumes`, `/mnt`, `/media` and `/tmp` are walked;
- credential stores (`~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.kube`, `~/.docker`, `~/.config/gh`, `~/.config/gcloud`, `~/.azure`, `~/.password-store`, keychains, browser profiles, …).

Links inside a skills tree follow the same rule. A tree is counted before it is read: one with more than 10,000 entries (each linked directory has its own 10,000-entry budget) is not read. A refused or oversized tree is reported by SKL-002 as a warning, "not scanned", with the reason; the other skill and IOC checks say "not verified" for it.

### `vaso detect`

Lists installed AI agents without running any security checks. Useful for verifying which agents VASO can see before running a full scan.

The reported version is that of the CLI your `PATH` resolves. Other copies of the same agent at different versions (an older npm global, a copy under another nvm/fnm/asdf/mise Node version, or a past version a self-updating installer keeps on disk) are listed as **Other copies**, and the advisory checks (ADV-001/003/004) evaluate each of them, so a vulnerable leftover is flagged even when the copy you run is current.

```
vaso detect [options]
```

| Option | Description |
|--------|-------------|
| `-a, --agent <type>` | Detect a specific agent only: `openclaw`, `nanoclaw`, `picoclaw`, `ironclaw`, `nanobot`, `zeroclaw`, `nemoclaw`, `openshell`, `hermes`, `lyrie`, `atomic-agent`, `claude-code`, `claude-desktop`, `chatgpt-desktop`, `codex`, `opencode`, `gemini-cli`, `qwen-code`, `copilot-cli`, `cursor-cli`, `windsurf`, `devin`, `abacus`, `meta-muse`, `comet`, or `grok-bot` |
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
| `--host-inventory` | With `-f json` on one host, output `{ installations, hostInventory }` instead of the bare installation array, adding MCP servers no agent owns and servers shared between agents (multi-host JSON always includes `hostInventory` per host) |
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

Terminal output shows each agent's type, version, install directory, config file count, skills directory, and gateway info. JSON output returns the full `AgentInstallation` array; with `--host-inventory` it returns `{ installations, hostInventory }`, where `hostInventory` has the same shape as in `vaso scan` JSON. Multi-host JSON gives each host `{ host, label, installations, hostMcp, hostInventory }`.

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

# Gate a CI pipeline on warnings as well as critical findings
vaso skill audit ./skills/new-skill --fail-on warning
```

Exit code 1 is returned if any finding at or above `--fail-on` (default `critical`) is detected. Exit 0 means only that nothing reached that threshold — with the default, warnings may still be reported, so read the report (or use `--fail-on warning`) before treating a skill as safe. If the path does not exist or is not a directory, VASO exits with code 2 without scanning; only an empty directory is reported as having nothing to audit (exit 0) — documentation, `package.json` and config files are audited too (SKL-007, IOC checks). Skills symlinked in from elsewhere are followed and scanned.

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
| `--project-rules` | Also load the working directory's `.vaso/rules/` (their `fix.set` is never applied) |
| `--rollback [backup]` | Undo the last fix run; run it again to undo the one before. Name a backup (from `~/.vaso/backups/`, owner-only) to restore that one |
| `--no-color` | Disable colored output |

When neither `--yes` nor `--dry-run` is set, VASO enters **interactive mode** and prompts for each fixable finding:

```
  CFG-001 [critical]
  Gateway is bound to 0.0.0.0 — accessible from all network interfaces
    /home/alice/.openclaw/openclaw.json
  Fix: Rebind the gateway to loopback (127.0.0.1, or gateway.bind "loopback")
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

`vaso fix` changes only regular files and folders inside the home of the installation's user (where its backup can restore them): never a file outside that home (`/etc/...`, `/opt/...`), a symlink, a hard-linked file, a FIFO or device, nor a file that a linked folder above it takes into a credential store (`~/.aws`, `~/.ssh`, …), a shell startup file or `/etc` its own path doesn't name. As root, it changes only files owned by that home's owner. The scan applies the same rules: such a finding's message ends with "not changed by vaso fix: <path> …", and when that covers every file the fix would change, the finding is reported as not fixable and `vaso fix` doesn't offer it.

`vaso fix` exits `0` when every fix it ran was applied, was already in place, was skipped, or had nothing left but files the scan named as "not changed by vaso fix" (reported as "nothing left that vaso fix may change"). It exits `1` when a fix failed — an error, or a refused file the scan did not name — and `2` when it cannot run.

**Which checks can be fixed.** 51 built-in checks have an automatic fix (a finding is offered only when the scan marks it fixable; every other finding carries guidance text only):

| Category | Checks |
|----------|--------|
| config | CFG-001, CFG-003, CFG-005, CFG-008, CFG-010, CFG-012, CFG-020 |
| policy | POL-003 |
| openclaw | OC-006 |
| nanoclaw | NC-002 |
| picoclaw | PCL-001, PCL-002, PCL-004 |
| ironclaw | IC-001, IC-005, IC-006, IC-007, IC-008, IC-012 |
| nanobot | NB-003 |
| zeroclaw | ZC-001, ZC-003, ZC-004, ZC-005, ZC-006, ZC-008, ZC-011, ZC-012, ZC-013, ZC-014, ZC-016 |
| lyrie | LY-001, LY-009, LY-018 |
| hermes | HM-003 |
| atomic-agent | AT-002, AT-003, AT-005 |
| openshell | OSH-002, OSH-004, OSH-005 |
| coding-agent | CD-002, CDX-003, OPC-001, GHC-001, ABA-001, ABA-010, GB-001, GB-007, GB-008, GB-015 |

Permission fixes remove group and other access (they never set a fixed mode such as 600); config fixes skip a value that is already in place. Your own [custom rules](#custom-rule-reference) can add fixes with `fix.set`.

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

The output directory contains one `attack-tree` and one `privilege-gradient` config file per installation, one `topology.<ext>` file (the `component` diagram) for the whole host, and a `README.md` with copy-paste `usecvis` commands. With a multi-host `-i` report, each host's subdirectory holds its own set.

### `vaso update`

Fetch the IOC (Indicators of Compromise) and advisory threat-intelligence feeds. Both feeds are signed with a pinned Ed25519 key (`src/ioc/public-key.ts`) and rejected on version rollback — see `SECURITY.md`. Verified feeds are cached under `~/.vaso/ioc/` and `~/.vaso/advisory/` (feed, signature, and `metadata.json`) and loaded on top of the bundled databases, which remain the offline baseline.

Feeds are published **at least monthly**, with out-of-band publishes for actively exploited issues — see the "Threat Feed Updates" section of `SECURITY.md` for the full policy.

```bash
vaso update                      # Fetch the latest signed feeds (whatever the cache's age)
vaso update --force              # Also re-install a feed of the cached version (repairs a damaged cache)
vaso update --url <url>          # Custom IOC feed URL (must still be signed with the pinned key)
vaso update --advisory-url <url> # Custom advisory feed URL (same signature requirement)
```

A feed older than the cached one is never installed, `--force` included. `vaso update` exits 2 when either feed can't be fetched or verified, so a cron job or CI step notices.

### `vaso mcp scan`

Scan MCP (Model Context Protocol) server configurations for security issues. This auto-discovers MCP configs from Claude Desktop, Claude Code, Gemini CLI, Qwen Code, Codex, GitHub Copilot CLI, Cursor, Windsurf, Devin CLI, Abacus.AI (CLI and Desktop), OpenCode (including `$OPENCODE_CONFIG`), Hermes, Atomic Agent, Nanobot, PicoClaw, Lyrie, VS Code (user and project `mcp.json`), and project-level config files. `CLAUDE_CONFIG_DIR`, `CODEX_HOME`, `COPILOT_HOME` and `GEMINI_CLI_HOME` relocations are followed.

```
vaso mcp scan [options]
```

| Option | Description |
|--------|-------------|
| `-f, --format <format>` | Output format: `terminal` (default), `json`, `sarif`, `markdown`, `html`, `csv`, `junit` |
| `-o, --output <file>` | Write report to a file instead of stdout |
| `-p, --path <paths...>` | Specific config file paths to scan (skips auto-discovery). `.toml` files are read as TOML (Codex) and `.yaml`/`.yml` as YAML (Hermes), anything else as JSON/JSONC. A path that is missing or doesn't parse is an error (exit 2) |
| `--resolve-packages` | Download npm-packaged (`npx`) MCP servers — download only, never executed — and analyze their source. Requires network access and `npm` on PATH; a package that cannot be downloaded is reported (`PACKAGE-RESOLVE`, with the reason) and the scan exits 3 (incomplete) |
| `--audit-deps` | Look up the exact versions of the servers' dependencies (from their lockfiles or installed copies) in [OSV.dev](https://osv.dev) for known vulnerabilities, in addition to the bundled advisories. Sends package names and versions only — never code, paths or config. Dependencies known only by a declared range are not looked up. If OSV can't be reached the scan continues with bundled advisories. Requires network access |
| `--fail-on <severity>` | Exit 1 on findings of this severity or higher: `critical` (default), `warning`, `info`, `none` |
| `--source <paths...>` | Analyze MCP server source directly — an entry file, a server checkout, or a Python package checkout (`pyproject.toml` + `src/<pkg>/`, all of its modules). For server authors, and for remote servers whose code you have but only connect to (`npx mcp-remote https://…`). On its own it scans only these servers (no config discovery); with `-p`, both. A path with no server source is reported and the rest are scanned, with exit 3 (incomplete); if nothing at all is scannable, exit 2 |
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

Known limits of the source analysis (static, no code is run):

- Tool input is traced within one file. Input a handler passes to a helper in another of the server's modules (`import { readDoc } from './docs.js'`) is not followed into that module, so a sink there is not tied to tool input. Code execution in helper modules is still reported by MCP-004.
- SQL text passed to sqlite's generic methods (`db.exec`, `run`, `all`, `get`) counts only when its keywords are written in capitals; `db.query`/`prepare`/`execute`/`raw`/`$queryRawUnsafe` take any case.
- A server started through a package script (`npm start`, `pnpm --dir d start`, `deno task`) is followed through `&&` chains, nested `npm run`, `sh -c` and `python -m` of the checkout's own module. Only the first 8 KiB of a script are read. A script it can't follow, or a package script whose directory the config doesn't set (no `cwd`), is listed by MCP-001 as "source not analysed" rather than guessed.

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

### Plugins (`vaso ext`)

User plugins are JavaScript modules that add checks, agent adapters or report formats.

> **Warning:** a plugin is code. VASO imports every plugin in `~/.vaso/plugins/` on every `vaso` command (`scan`, `detect`, `fix`, `mcp`, `update`, …), and it runs with the rights of the user running VASO (root, if you run VASO as root). VASO doesn't check a plugin's file permissions or origin. Install only plugins you have read and trust, and keep `~/.vaso/plugins/` writable only by you.

**Where they go.** VASO loads, in name order, each entry of `~/.vaso/plugins/` that is:

- a `.js` or `.mjs` file (ES module syntax), or
- a directory with a `package.json` `main`, else an `index.mjs` or `index.js`.

Entries whose names start with `.` or `_` are skipped (use this to disable a plugin without deleting it).

**Module shape.** The module's default export (or the module itself) is an object with an optional `meta` and a `register(api)` function, which may be async:

| `api` member | Use |
|--------------|-----|
| `registerCheck(check)` | Add one check: `{ id, name, category, severity, description, supportedAgents?, excludedAgents?, supportedPlatforms?, run(context), fix?(context) }`. `run` returns `{ id, name, category, severity, passed, message, evidence? }`; `context` holds `installation`, `configs` (each with `filePath`, `format`, `data`, `raw`), `platform`, `fs` and `skillFiles` |
| `registerChecks(checks)` | Add several checks |
| `registerAdapter(adapter)` | Add an agent adapter (`detect()`, `getConfigPaths()`, `getSkillsDir()`, `getGatewayInfo()`; `custom-agent-adapter.mjs` in the examples shows the full shape) |
| `registerReporter(format, factory)` | Add an output format for `-f <format>`; built-in formats can't be replaced |

Use one of the built-in categories (listed in [Custom rule reference](#custom-rule-reference)) for `category`, and `critical`, `warning` or `info` for `severity`. A check ID already taken — by a built-in check or another plugin — is refused. Read files through `context.fs` (not `node:fs`) so the check also works on remote and `--snapshot` scans.

A minimal check plugin, `~/.vaso/plugins/debug-flag.mjs`:

```js
export default {
  meta: {
    name: 'debug-flag',
    version: '1.0.0',
    description: 'Flags DEBUG=true in agent configs',
  },
  register(api) {
    api.registerCheck({
      id: 'USR-100',
      name: 'Debug flag left on',
      category: 'config',
      severity: 'warning',
      description: 'An agent config sets DEBUG to true',
      async run(ctx) {
        const evidence = [];
        for (const cfg of ctx.configs) {
          cfg.raw.split('\n').forEach((line, i) => {
            if (/\bDEBUG['"]?\s*[:=]\s*['"]?true/i.test(line)) {
              evidence.push({ file: cfg.filePath, line: i + 1, snippet: line.trim() });
            }
          });
        }
        return {
          id: 'USR-100',
          name: 'Debug flag left on',
          category: 'config',
          severity: 'warning',
          passed: evidence.length === 0,
          message: evidence.length === 0 ? 'No DEBUG flag found' : `DEBUG=true in ${evidence.length} place(s)`,
          evidence,
        };
      },
    });
  },
};
```

```bash
vaso ext list [-f terminal|json]   # Plugins found, their status and what each registered
vaso ext info <name> [-f json]     # One plugin (by meta.name, else the file name); unknown name exits 2
```

**Errors are isolated.** A plugin that fails to import, has no `register()` function, throws from `register()` or registers a taken ID is marked `error` (with the reason) in `vaso ext list`, and a warning is printed; the command carries on with the other plugins. A check whose `run()` throws is reported as errored, and the scan exits `3` (incomplete). Isolation covers errors only — it is not a sandbox.

More complete examples (batch registration with a `fix()`, a custom reporter, an adapter for a new agent) are in the repository at [examples/plugins](https://github.com/vulnex/vaso/tree/main/examples/plugins); they are not part of the npm tarball.

### Custom rules (`vaso rules`)

Declarative YAML rules add your own checks to `vaso scan` and `vaso fix`: a config value (`config`), a regex over config or skill files (`pattern`) or a file that must or must not exist (`file_exists`), optionally with a `fix` that sets one config key. The full format is in the [Custom rule reference](#custom-rule-reference).

```bash
vaso rules init [--dir <path>] [--force]   # Write a commented example.yaml (default ~/.vaso/rules/)
vaso rules list [-f json]                  # Rules that scan/fix would load, and where from
vaso rules validate <file> [-f json]       # Validate one rule file
```

### `vaso probe`

Advanced — manage probe snapshots for remote scanning. The probe is normally push-deployed automatically by `vaso scan --host` / `--inventory`; these commands let you inspect what the probe will collect or validate a snapshot file by hand.

```bash
vaso probe manifest               # Print the manifest the probe will use
vaso probe validate <snapshot>    # Validate a probe snapshot JSON file
```

See [`network-scanning-guide.md`](network-scanning-guide.md) for the full SSH workflow.

## Custom rule reference

### Where rules load from

`vaso scan` loads rules from three places, and `vaso fix` from the first and third (other commands don't load rules). `vaso scan --no-custom-rules` skips all three:

| Source | Loaded | Notes |
|--------|--------|-------|
| `~/.vaso/rules/*.yaml`, `*.yml` | always | Your own (or your organisation's) rules. Files starting with `.` are ignored |
| `--rules <paths...>` (`scan` only) | when named | Files or directories (a directory loads its `*.yaml`/`*.yml`). A file that can't be read, or whose rules don't validate, exits `2`. Replaces a `~/.vaso/rules/` rule with the same ID (with a warning) |
| `.vaso/rules/*.yaml`, `*.yml` in the working directory | only when you trust the project | A cloned repository can ship these, so they load only with `--project-rules` or when the project's path is listed in `~/.vaso/trusted-projects`. Otherwise `scan`/`fix` print one notice ("Skipped N project rule file(s)…", hidden by `--silent`) and `vaso rules list` shows them as "untrusted (not loaded)" |

**`~/.vaso/rules/` must be yours alone.** A rule can carry a fix that `vaso fix` applies, so a rule file loads only when nobody else could have written or replaced it. A file is skipped, with a warning saying why, when:

- the file, `~/.vaso/rules/` or `~/.vaso` is writable by group or others (group write is allowed when the group is your own private group);
- any of them is owned by someone other than you or root;
- the file is a symlink whose target sits in a directory others can write (unless it is sticky, like `/tmp`).

`chmod 700 ~/.vaso ~/.vaso/rules` and `chmod 600` the files (`vaso rules init` creates them that way). Rule files larger than 4 MiB are not read.

**`~/.vaso/trusted-projects`** lists one absolute project path per line (the directory you run VASO from; `#` starts a comment, relative lines are ignored); a project reached through a symlink matches its real path. VASO uses the file only when it is a regular file of at most 64 KiB, owned by you (or root), not writable by group or others, inside a `~/.vaso` with the same properties; otherwise it is ignored with a warning.

**Trusted project rules** run like your own rules with two exceptions: their `fix.set` is ignored (only `fix.guidance` text stays — move the rule to `~/.vaso/rules/` to keep its fix; `vaso fix` has no `--rules` option), and they never replace a rule ID already defined in `~/.vaso/rules/` or by `--rules` (the project rule is skipped with a warning naming both files).

**IDs.** Within one source, the first definition of an ID wins and later ones are skipped with a warning. A rule whose ID matches a built-in check (or a plugin's check) is skipped with a warning; `vaso rules validate` reports it as an error.

Rules run on every scan target: local, `--host`/`--inventory` and `--snapshot` scans.

### File format

A rule file is a YAML document with a top-level `rules` list. Each rule has these fields:

| Field | Required | Value |
|-------|----------|-------|
| `id` | yes | 1–64 letters, digits, `.`, `_` or `-`, starting with a letter or digit (`ORG-001`). Must not be a built-in check ID |
| `name` | yes | Short title shown in reports |
| `description` | yes | What the rule enforces; shown in the finding message |
| `category` | yes | One of `config`, `skills`, `ioc`, `network`, `runtime`, `policy`, `mcp`, `openclaw`, `nanoclaw`, `picoclaw`, `ironclaw`, `nanobot`, `zeroclaw`, `lyrie`, `hermes`, `atomic-agent`, `openshell`, `advisory`, `coding-agent` |
| `severity` | yes | `critical`, `warning` or `info` (scored like built-in checks) |
| `agents` | no | List of agent types the rule applies to (the `-a` values, e.g. `[claude-code, codex]`). Without it, the rule runs against every detected agent |
| `platforms` | no | List of platforms: `linux`, `darwin`, `win32`, `freebsd`, `openbsd`, `netbsd`, `sunos`, `aix`, `android`, `haiku`, `cygwin` |
| `config` / `pattern` / `file_exists` | exactly one | The rule type, below |
| `fix` | no | `set` + `value`, and/or `guidance`, below |

#### `config` — a config value

Evaluated against each parsed config file of each agent in scope (JSON, JSONC/JSON5, YAML, TOML, `.env`).

| Sub-field | Value |
|-----------|-------|
| `path` | Dotted key path (`gateway.bind`, `permissions.defaultMode`); list items by index (`servers.0.url`). A key that itself contains a dot can't be addressed |
| `operator` | One of the operators below |
| `value` | Compared with the config value (not used by `exists` / `not-exists`) |
| `pass_when` | `no-match` (default): the rule **fails** when the condition is true — write the condition as the bad state. `match`: the rule fails when the condition is false — write it as the required state |

Operators:

| Operator | True when |
|----------|-----------|
| `eq` | The value equals `value` (deep equality for lists and objects; types must match: `"true"` is not `true`) |
| `neq` | The value does not equal `value` (a missing key counts as not equal) |
| `in` | The value equals one item of `value`, which must be a list |
| `not-in` | The value equals no item of the `value` list (a missing key counts as not in it) |
| `exists` | The key is present (with any value, including `null`) |
| `not-exists` | The key is absent |
| `gt` | The value and `value` are both numbers and the value is greater (`"8080"` as a string never compares) |
| `lt` | Both are numbers and the value is smaller |
| `matches` | The value is a string and the regular expression `value` (JavaScript syntax, no flags, at most 500 characters) finds a match in it |
| `contains` | The value is a list holding an item equal to `value`, or a string containing the string `value` |

#### `pattern` — a regex over files

| Sub-field | Value |
|-----------|-------|
| `regex` | JavaScript regular expression (no flags, at most 500 characters), tested against each line |
| `target` | `configs` (default — the agent's config files), `skills` (its skill files) or `all` |
| `message` | Optional evidence text; placeholders `{{file}}`, `{{line}}`, `{{snippet}}`, `{{match}}`. Default: `Pattern match in {{file}}:{{line}} — {{snippet}}` |

Each matching line is one piece of evidence.

#### `file_exists` — a file that must or must not exist

| Sub-field | Value |
|-----------|-------|
| `path` | Absolute path, or a path relative to the agent's install directory (`~/.openclaw`, `~/.claude`, …). `~` is not expanded |
| `pass_when` | `not-exists` (default): fails when the file exists. `exists`: fails when it is missing |

#### `fix`

| Sub-field | Value |
|-----------|-------|
| `set` | Dotted key path `vaso fix` writes (`__proto__`, `prototype`, `constructor` and empty segments are rejected). Applied only by `config` rules, only to the config files the rule failed on, never as a dotted key into a `.env` file; ignored in project rules |
| `value` | The value `set` writes |
| `guidance` | Text shown as the finding's fix advice (any rule type) |

A `fix` needs `set` or `guidance`. `vaso fix` backs up files before writing, as for built-in fixes.

### Regex safety

Rule regexes (`pattern.regex` and the value of `matches`) are checked when a rule loads and by `vaso rules validate`. A pattern that can backtrack super-linearly is rejected and the rule skipped with a warning: nested or overlapping quantifiers (`(a+)+$`, `(a|aa)+$`, `(\w+\s?)*`), and chains of three or more overlapping loops, counting the unanchored search over start positions as one (`.*a.*a.*b`, `\d+\d+x`). Patterns the checker can't analyse are rejected too.

At run time each regex sees at most the first 4,096 characters of a line or value. A pattern rule may spend 5 seconds matching per check run, and all rules together 15 seconds per host; past that the rule stops, its result is marked errored, and the scan exits `3` (incomplete).

Values a rule quotes in its findings (a config value, the matched line, `{{match}}`/`{{snippet}}`) are masked like every other credential VASO reports: a value under a credential-like key (`api_key`, `token`, `password`, …) and well-known token formats show as `***`.

### Examples

Each of these passes `vaso rules validate`. A `config` rule with a fix:

```yaml
rules:
  - id: ORG-001
    name: Claude Code default mode is not bypassPermissions
    category: coding-agent
    severity: critical
    description: Claude Code must not skip permission prompts by default
    agents: [claude-code]
    config:
      path: permissions.defaultMode
      operator: eq
      value: bypassPermissions
    fix:
      set: permissions.defaultMode
      value: default
```

A `pattern` rule over skill files:

```yaml
rules:
  - id: ORG-002
    name: Internal hostname in skill code
    category: skills
    severity: warning
    description: Skills must not reference internal corp hosts
    pattern:
      regex: "\\b[a-z0-9-]+\\.corp\\.example\\.com\\b"
      target: skills
      message: "Internal host {{match}} in {{file}}:{{line}}"
    fix:
      guidance: Move the host name to configuration
```

A `file_exists` rule that requires a file:

```yaml
rules:
  - id: ORG-003
    name: OpenClaw audit log present
    category: openclaw
    severity: info
    description: The OpenClaw state directory should keep an audit log
    agents: [openclaw]
    platforms: [linux, darwin]
    file_exists:
      path: logs/audit.log
      pass_when: exists
    fix:
      guidance: Enable audit logging in openclaw.json
```

### Commands

- `vaso rules init [--dir <path>] [--force]` writes a commented `example.yaml` (mode 600; a new directory is created 700) into `~/.vaso/rules/`, or `--dir`. It refuses to overwrite an existing file (exit `2`) unless `--force` is given. Files written to another directory load only with `--rules <dir>` (or, for `./.vaso/rules`, when the project is trusted).
- `vaso rules validate <file> [-f json]` checks one file: YAML syntax (a key repeated in one mapping is an error), every field, regex safety, and IDs that a scan would skip (a built-in check ID, or one defined twice in the file). Exit `0` when every rule is valid, `1` on any invalid rule or YAML error (in both formats), `2` when the file can't be read. `-f json` prints `{ "valid", "rules", "errors" }`.
- `vaso rules list [-f json]` lists the rules `scan`/`fix` would load with their file, plus untrusted project rules (status `untrusted` in JSON), and prints load warnings to stderr.

## Exit Codes

`vaso scan` exits non-zero when findings reach the threshold set by `--fail-on`:

| Code | Meaning |
|------|---------|
| `0` | Scan completed; no findings at or above the `--fail-on` threshold |
| `1` | Findings at or above the threshold |
| `2` | VASO could not run: invalid CLI arguments (e.g. `--silent` without an output destination, `--parallel 0`), an unreadable snapshot or inventory file, or an internal error |
| `3` | Scan incomplete: one or more remote hosts could not be scanned (unreachable, authentication failed, probe error, or probe output that fails the same checks as a `--snapshot` file — not JSON, the wrong shape, over the probe's size limits), or a check or adapter errored — threw, returned no result, or ran longer than the per-check timeout (5 minutes; `VASO_CHECK_TIMEOUT=<seconds>` changes it) — so findings may be missing. The errored checks are listed in the report. Takes precedence over `1`, so CI can tell "not scanned" apart from "findings" |

**`CONFIG-LOAD` never sets exit code 3.** A config file VASO can't read or parse (permission denied, malformed JSON/YAML/TOML, an unreadable config directory) is reported as a `CONFIG-LOAD` *finding* about the host — severity `warning`, listed with the file and the reason — not as an incomplete scan: VASO ran every check, and the unreadable file is the result. Like any finding it counts toward `--fail-on`, so it exits `1` with `--fail-on warning` or `info` and `0` with the default `critical`. Use `--fail-on warning` in CI if an unreadable agent config should fail the build.

The other commands use the same codes: `skill audit` and `mcp scan` exit `1` on findings at or above their `--fail-on` (default `critical`), `mcp scan` exits `3` when a result errored (for example a package `--resolve-packages` couldn't download — the `PACKAGE-RESOLVE` result says why), and every command exits `2` when it cannot run — a command-line error (unknown option or command, a missing or extra argument), a missing or unreadable input (`skill audit <path>`, `mcp scan/list --path`, `visualize -i`, `probe validate`), an unknown name (`ext info`), or an invalid option value such as `--ssh-timeout abc`. `probe validate` exits `2` for any snapshot it can't use — unreadable, not JSON, or failing validation (over the probe's size limits, a relative `homedir`, a malformed `privilege` block).

`--fail-on` accepts `critical` (default), `warning`, `info`, or `none`. Use `--fail-on none` to never fail on findings — useful for scans that only produce reports.

```bash
vaso scan --fail-on critical    # Default — only critical findings fail CI
vaso scan --fail-on warning     # Warning or critical fails CI
vaso scan --fail-on none        # Exit 0 unless VASO errors (2) or the scan is incomplete (3: a host unscanned, a check errored)
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

Each agent starts at 100 and loses points for each failed check (once per check, however much evidence it has), down to a floor of 0:
- **Critical** finding: -12 points
- **Warning** finding: -5 points
- **Info** finding: no penalty

The weights are fixed.

When several agents are scanned, the headline score and grade (`totalScore` / `totalGrade` in JSON) are those of the **weakest agent**, not an average: one wide-open agent is an exposure however many others are clean. The mean of the per-agent scores is still reported as the fleet average (`fleetAverage` in JSON; "Fleet average" in terminal, Markdown and HTML reports). With no agents detected the score is 100.

## Security Checks

VASO runs **368 checks across 19 categories**.

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
| OpenClaw | OC-* | 7 | Sub-agent config downgrade, legacy bot dirs, `OPENCLAW_HOME`/`OPENCLAW_STATE_DIR`/`OPENCLAW_CONFIG_PATH` redirect, profile downgrade, memory file perms, `/etc/openclaw` writable (retired — OpenClaw never reads it; always passes), dangerous gateway/tool/hook/browser overrides (OC-008) |
| NanoClaw | NC-001–005 | 5 | Overbroad mount allowlist (`allowedRoots`), host config/credential exposure, checkout/state exposure, webhook listener on all interfaces, skills dirs writable |
| PicoClaw | PCL-001–007 | 7 | Workspace restriction off, exec deny list disabled or bypassed, channels open to any sender (empty `allow_from` allows everyone), exec reachable from chat channels, weakly guarded `pico` WebSocket, public web launcher without a dashboard password, tool path allowances reaching credentials |
| IronClaw | IC-001–014 | 14 | 1.x (Reborn) and 0.x: WebUI/listener bind, cleartext LLM endpoints, WebUI token and master-key exposure, `local-dev-yolo` host access, approval policy, sandbox (0.x), permissive WebUI CORS, world-readable state DB |
| Nanobot | NB-001–012 | 12 | Open channels (`allowFrom: ["*"]`, open DM policy), plaintext secrets, workspace restriction, exec sandbox/allow patterns, SSRF whitelist, writable prompt/memory/cron files, unauthenticated WebUI, readable chat history, API server exposure, unpinned MCP packages |
| ZeroClaw | ZC-001–016 | 16 | V3 schema: plaintext/XOR secrets, gateway bind and pairing, `full` risk level, filesystem scope, open peer groups, open skills/scripts, WhatsApp session perms, browser/HTTP private-host access, sandbox, unrestricted commands/auto-approve, relaxed gateway safeguards |
| Lyrie | LY-001–020 | 20 | Checkout `.env` + `~/.lyrie` state: Shield mode/binary, channel DM policy, secrets-file perms, WebChat exposure/origins, pairing and edit ledgers, local-mode leaks, `NODE_ENV=development` SSRF gap, broad `LYRIE_FS_ROOT`, readable memory DB |
| Hermes | HM-001–011 | 11 | Plaintext API keys, env/credentials perms, API-server bind without auth, permissive CORS, plaintext inference endpoints, approvals-off, Tirith pre-exec scanner state, MCP stdio shell-c / unpinned packages, administrator-managed scope writable by others; settings judged after the managed `/etc/hermes` layer is applied |
| OpenShell | OSH-001–014 | 14 | Gateway TLS disabled, unauthenticated users, OIDC over plaintext HTTP, non-expiring SSH/sandbox credentials, `retain_last_valid` policy validation, fail-open or plaintext interceptors/middleware, resource admission off (critical with caller driver config), readable CA/JWT/TLS keys, key-encryption key, credential database and sandbox tokens, writable gateway config or CLI gateway metadata, CLI without TLS verification; live sandbox policies: network rules open to any program (`/**`), `tls: skip` / uninspected credentials / allow-all MCP / no protocol / `access: full` / audit-only rules, `allowed_ips` of /8 or wider and `host.openshell.internal`, writable system paths |
| Atomic Agent | AT-001–011 | 11 | Raised approval ladder (level 4/5), unrestricted read scope, unapproved HTTP egress, plaintext secrets in config.json, `.env`/mail-session perms, `pure_read` MCP trust, MCP stdio/transport hygiene, secretless webhooks, subscription-CLI lockdown overrides, plaintext inference endpoints, world/group-readable memory, sessions and traces |
| Coding Agent | CC, CD, CG, CDX, OPC, GEM, QC, CUR, GHC, WS, DEV, ABA, MM, PC, GB | 151 | Claude Code (12), Claude Desktop (10), ChatGPT Desktop (6), Codex (10), OpenCode (12), Gemini CLI (12), Qwen Code (10), Cursor (15), GitHub Copilot CLI (9), Windsurf/Devin Desktop (9), Devin CLI (10), Abacus.AI CLI/Desktop (15), Meta Muse (3), Perplexity Comet (2), Grok Bot (16): sandbox/approval policy, plaintext credentials, MCP pinning, broad allow rules, memory-file secrets, transport security |

Server-only checks (gateway/network/runtime concepts, mostly in CFG, NET, RUN, and POL) are automatically excluded for coding agents and desktop apps to avoid false positives — interactive coding CLIs have a different threat model than autonomous server agents.

## Supported Agents

VASO ships twenty-six adapters. Each implements `detect()`, `getConfigPaths()`, `getSkillsDir()`, and `getGatewayInfo()` against its framework's on-disk layout.

### Autonomous frameworks

| Adapter | Config locations | Formats |
|---------|------------------|---------|
| OpenClaw | `$OPENCLAW_STATE_DIR` (the state directory), `$OPENCLAW_HOME/.openclaw` (`OPENCLAW_HOME` replaces the home directory), `~/.openclaw`, `~/.openclaw-<profile>`, `~/.clawdbot` (only while no `~/.openclaw` config exists — `~/.moltbot` is never loaded and only reported by OC-003 as a leftover); `$include` files are followed (confined to the config dir or `$OPENCLAW_INCLUDE_ROOTS`); `$OPENCLAW_CONFIG_PATH` names the config file | JSON5/JSON, YAML, ENV |
| NanoClaw | v2 git checkout (`package.json`, `.env`; found via its service unit or common locations), `~/.config/nanoclaw/mount-allowlist.json` | JSON, ENV |
| PicoClaw | `$PICOCLAW_HOME` (default `~/.picoclaw`): `config.json`, `.security.yml`, `auth.json`, `launcher-config.json`; skills in `workspace/skills` | JSON, YAML |
| IronClaw | 1.x: `$IRONCLAW_REBORN_HOME` (default `~/.ironclaw/reborn/`); 0.x: `~/.ironclaw/` | TOML, JSON, ENV |
| Nanobot | `~/.nanobot/config.json` + workspace (`agents.defaults.workspace`) | JSON |
| ZeroClaw | `$ZEROCLAW_CONFIG_DIR` (default `~/.zeroclaw/`): `config.toml` (V3), `auth-profiles.json` | TOML, JSON |
| NemoClaw | `~/.nemoclaw/`, `/etc/nemoclaw/` | JSON, YAML |
| Hermes | `$HERMES_HOME` (default `~/.hermes/`): `config.yaml`, `.env`; administrator-managed `config.yaml` / `.env` in `$HERMES_MANAGED_DIR` or `/etc/hermes/`, applied over the user's files (`.env` read with python-dotenv's rules, `${VAR}` expanded) | YAML, ENV |
| Lyrie | git checkout `.env` (found via its service unit or common locations, `package.json` name `lyrie-agent`) + `~/.lyrie/` state (`config.json`, `mcp.json`, pairing/edit ledgers, memory) | ENV, JSON |
| Atomic Agent | `~/.atomic-agent/` or `$ATOMIC_AGENT_STATE_DIR` (config.json, .env, skills/; MCP servers also discovered by `vaso mcp`) | JSON, ENV |

### Agent sandbox runtime

| Adapter | Config locations | Formats |
|---------|------------------|---------|
| NVIDIA OpenShell | `$XDG_CONFIG_HOME/openshell/` (`gateway.toml`, `gateway.env` — which can redirect the TOML, database and TLS dir, as NemoClaw does — `active_gateway`, `gateways/<name>/`), `$XDG_STATE_HOME/openshell/` (gateway database, key-encryption key, TLS, sandbox tokens), Homebrew `<prefix>/var/openshell/`, snap per-user `~/snap/openshell/common/` (`.config/openshell/gateway.toml`, state, TLS) with `/var/snap/openshell/common/gateway.toml` as fallback. With the `openshell` CLI installed, VASO reads each sandbox's effective policy and the global policy from the user's active gateway with read-only queries (`sandbox list`, `policy get`); `$OPENSHELL_SANDBOX_POLICY` is read too. Remote scans run the same queries through the probe. NemoClaw installs report their gateway here | TOML, ENV, JSON, YAML |

### Interactive coding agents

| Adapter | Config locations | Formats |
|---------|------------------|---------|
| Claude Code | `~/.claude/`, `~/.claude.json`, project `.claude/` | JSON |
| Codex | `~/.codex/config.toml`, `~/.codex/auth.json` | TOML, JSON |
| OpenCode | `$XDG_CONFIG_HOME/opencode/opencode.json[c]`, `$XDG_DATA_HOME/opencode/auth.json` | JSON, JSONC |
| Gemini CLI | `~/.gemini/settings.json`, OAuth credential files (`oauth_creds.json`, `google_accounts.json`, `mcp-oauth-tokens.json`); project `.gemini/`; workspace settings apply only in a trusted folder (`trustedFolders.json`, `$GEMINI_CLI_TRUSTED_FOLDERS_PATH`, `$GEMINI_CLI_TRUST_WORKSPACE`, `$GEMINI_RESTRICTED_MODE`, `folderTrust.enabled`) | JSONC |
| Qwen Code | `~/.qwen/settings.json` (multi-provider auth: OpenAI/Anthropic/Gemini/Dashscope/Bailian); project `.qwen/`; with `folderTrust` on, workspace settings apply only in a trusted folder (`$QWEN_CODE_TRUSTED_FOLDERS_PATH`) | JSONC |
| GitHub Copilot CLI | `~/.copilot/config.json`, `settings.json`, `command-history-state.json`, `session-state/`; workspace `.mcp.json` + `.github/lsp.json` | JSONC |
| Cursor CLI/IDE | `~/.cursor/` (`cli-config.json`, `mcp.json`, `permissions.json`, `sandbox.json`, `hooks.json`); project `.cursor/`; IDE user-data dir (`~/Library/Application Support/Cursor/`, `~/.config/Cursor/`, `%APPDATA%\Cursor\`: `User/settings.json`, `User/globalStorage/state.vscdb`); IDE-only installs via `/Applications/Cursor.app` | JSON |
| Windsurf / Devin Desktop | `~/.codeium/windsurf/` (`mcp_config.json`, `hooks.json`, memories, workflows, `user_settings.pb`), `~/.config/devin/mcp_config.json`; Cascade hooks also from `/etc/devin/hooks.json` / `/Library/Application Support/Devin/hooks.json` (legacy Windsurf paths as fallback) and the workspace `.devin/hooks.json` (else `.windsurf/hooks.json`); editor user-data `{Windsurf,Devin}` dirs (`~/Library/Application Support/`, `~/.config/`, `%APPDATA%`); version from the app's `product.json` | JSON |
| Devin CLI | `$XDG_CONFIG_HOME/devin/` (default `~/.config/devin/`: `config.json`, `mcp_config.json`, `AGENTS.md`), `$XDG_DATA_HOME/devin/credentials.toml`; project `.devin/` (found by walking up to the repo root) incl. `hooks.v1.json`; `%APPDATA%\devin\` on Windows | JSONC, TOML |
| Abacus.AI CLI / AbacusAI Desktop | `~/.abacusai/` (`config.json`, `mcp.json`, `trusted-workspaces.json`, `keystore.enc`, `desktop/mcp-<mode>.json`, `desktop/agent-config-<mode>.json`), project `<workspace>/.abacusai/` (ignored until the workspace is trusted); AbacusAI Desktop user data (`~/.config/AbacusAI Desktop`, `~/Library/Application Support/AbacusAI Desktop`); CLI copies: `~/.abacusai/bin`, npm `@abacus-ai/cli`, `~/.abacusai/versions/`, the desktop app's bundled CLI | JSON |

### Agentic desktop apps

| Adapter | Config locations | Formats |
|---------|------------------|---------|
| Claude Desktop | `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS), `%APPDATA%\Claude\claude_desktop_config.json` (Windows); MCPB extensions under `Claude Extensions/` | JSON |
| ChatGPT Desktop | `/Applications/ChatGPT.app` (current app, `com.openai.codex`) and `/Applications/ChatGPT (Classic).app` (`com.openai.chat`) + `~/Library/Application Support/com.openai.chat/`; preferences in `~/Library/Preferences/com.openai.chat*.plist` (macOS only) | plist |
| Meta Muse | `/Applications/Muse.app`, `~/Library/Preferences/com.meta.endo.plist`, `~/Library/Application Support/com.meta.endo/` (macOS only; initial coverage) | plist |
| Perplexity Comet | `/Applications/Comet.app` + Chromium profile `~/Library/Application Support/Comet/` (macOS) or `%LOCALAPPDATA%\Perplexity\Comet\User Data` (Windows): session-data permissions, extension inventory | — |
| Grok Bot | Data root `~/.grokbot/` (`settings.json`, `local-exec-daemon-credential.json`, `local-tool-standing-grants.v1.json`, `local-computer-use-gate.json`, daemon log; relocated by `$SAND_DATA_ROOT` / `$SAND_USER_DATA_DIR`; pre-rename `~/.cursor/sand/`); Electron user data `~/.config/Grok Bot/` (Linux), `~/Library/Application Support/Grok Bot/` (macOS), `%APPDATA%\Grok Bot\` (Windows; the pre-rename `%APPDATA%\Sand\` while the app still uses it) with `sand-secrets.json`, `user-secrets.json`, `Cookies`; app `/opt/Grok Bot` (.deb/.rpm) or `/Applications/Grok Bot.app`; version from `desktop-status.json`, the macOS Info.plist or, for a .deb that has never run, its package metadata (local scans only). Secret stores and standing approvals are collected metadata-only by remote scans; endpoint overrides read from the environment (GB-012): `$SAND_BACKEND_URL` / `$CURSOR_API_BASE_URL`, `$SAND_HOST_GATEWAY_URL`, `$SAND_CURSOR_WEBSITE_URL` / `$CURSOR_WEBSITE_URL`, `$SAND_HTTPS_PROXY`, `$SAND_EGRESS_TUNNEL_URL` | JSON |

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
- VS Code user `settings.json` (`mcp.servers`; per-OS user-data dir)

**Project-level configs:**
- `.mcp.json` (Claude Code project)
- `.cursor/mcp.json` (Cursor project)
- `.windsurf/mcp.json` (Windsurf project)
- `.devin/mcp_config.json`, `.devin/mcp_config.local.json` (Devin CLI project)
- `.abacusai/mcp.json`, `.abacusai/config.json` (Abacus.AI project)
- `.vscode/mcp.json` and `.vscode/settings.json` `mcp.servers` (VS Code)
- `.codex/config.toml` (Codex project `[mcp_servers.<name>]`)
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

One row per check result and evidence item — a check with no evidence is one row, one with evidence (failed, or passed with informational evidence) a row per piece of evidence — designed for SIEM / data-warehouse ingestion (filter on `passed` for findings only). Cells that would start a spreadsheet formula are prefixed with `'`. Columns: `timestamp`, `agent`, `agent_name`, `check_id`, `check_name`, `category`, `severity`, `passed`, `message`, `file`, `line`, `snippet`, `detail`.

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

Each `--save-baseline` writes a timestamped copy, `~/.vaso/baselines/baseline-<timestamp>.json` (kept as history; VASO never deletes them), and the scope's "latest" file that `--diff` compares against. The latest files are per scope: `latest.json` for an unfiltered local scan, `latest-<agent>.json` with `-a`, `latest-<host>.json` / `latest-<agent>--<host>.json` for a snapshot or remote host (each `--host` target keeps its own). A `latest.json` written by VASO ≤ 1.3.0 with `-a` is still found by a matching `--diff -a`.

## CI/CD Integration

### GitHub Actions: the VASO action

The repository is a GitHub Action. It installs the release tarball, runs `vaso scan` on the runner and uploads the SARIF report to GitHub Code Scanning:

```yaml
name: VASO

on:
  push:
    branches: [main]
  schedule:
    - cron: '0 6 * * 1' # Weekly, Monday 06:00

permissions:
  contents: read
  security-events: write # SARIF upload

jobs:
  vaso:
    runs-on: self-hosted # a runner where the agents to check are installed
    steps:
      - uses: vulnex/vaso@v1.4.1
        with:
          fail-on: warning
```

| Input | Default | Meaning |
|-------|---------|---------|
| `version` | `v1.4.1` | VASO release to install (a `vX.Y.Z` tag installs the release tarball; a branch or SHA installs from git) |
| `agent` | all detected | Scan one agent only (`-a`) |
| `format` | `sarif` | Report format |
| `output` | `vaso-results.<ext>` | Report path |
| `fail-on` | `critical` | `--fail-on` threshold; the step fails at or above it |
| `working-directory` | `.` | Directory to run from |
| `upload-sarif` | `true` | Upload a SARIF report to Code Scanning (also when the scan found something) |
| `debug` | `false` | Pass `--debug` |
| `extra-args` | — | Extra `vaso scan` flags, e.g. `--host deploy@10.0.0.5` or `--rules .github/vaso-rules` |

The action's output `report-path` is the report's absolute path. `vaso scan` checks the machine it runs on: on a fresh GitHub-hosted runner there is usually no agent installed and the scan finds nothing. Use it on self-hosted runners and agent hosts, or with `extra-args: --host …` / `--inventory …`.

### GitHub Actions: checking a repository

To check what a repository ships — skills and MCP server configs — run `skill audit` and `mcp scan` on its files. Both exit `1` when findings reach `--fail-on`, which fails the step:

```yaml
name: VASO repository checks

on: [push, pull_request]

permissions:
  contents: read
  security-events: write

jobs:
  vaso:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-node@v4
        with:
          node-version: '20'

      - name: Install VASO
        run: |
          curl -fsSLo "$RUNNER_TEMP/vaso.tgz" https://github.com/vulnex/vaso/releases/download/v1.4.1/vaso-1.4.1.tgz
          npm install -g "$RUNNER_TEMP/vaso.tgz"

      - name: Audit skills
        run: vaso skill audit ./skills --fail-on warning -f sarif -o vaso-skills.sarif

      - name: Scan MCP config
        if: always() # run even when the skill audit failed
        run: vaso mcp scan -p .mcp.json --fail-on warning -f sarif -o vaso-mcp.sarif

      - name: Upload skill audit
        if: always() && hashFiles('vaso-skills.sarif') != ''
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: vaso-skills.sarif
          category: vaso-skills

      - name: Upload MCP scan
        if: always() && hashFiles('vaso-mcp.sarif') != ''
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: vaso-mcp.sarif
          category: vaso-mcp
```

Adjust `./skills` and `.mcp.json` to your layout (`mcp scan -p` takes several files; `--source <dir>` audits an MCP server's own code). A path that doesn't exist exits `2`, which also fails the job.

### Generic CI

```bash
vaso scan --fail-on critical -f json -o results.json
# 0 = nothing at or above critical, 1 = findings, 2 = VASO could not run,
# 3 = incomplete (a host unscanned or a check errored)
```

## Zero-Dependency Quick Scan

For fast triage or environments without Node.js, use the Bash quick-scan script. Installed via npm, it's symlinked onto your PATH alongside `vaso`:

```bash
vaso-quick
```

This runs 5 critical checks against an OpenClaw install (gateway binding, API key exposure, file permissions, sandbox status, auth bypass) using only standard Unix tools; it honours `OPENCLAW_STATE_DIR` and `OPENCLAW_HOME` and reads JSON, JSON5 and YAML configs. It exits 1 when any check fails and 0 otherwise. No Node.js or npm dependencies required at runtime.

You can also run the script directly without installing anything — fetch it once and execute:

```bash
curl -fsSL https://raw.githubusercontent.com/vulnex/vaso/main/bin/vaso-quick.sh | bash
```

## Data Storage

VASO keeps all local state under `~/.vaso/`:

| Path | Purpose |
|------|---------|
| `~/.vaso/baselines/` | Saved scan baselines for `--save-baseline` / `--diff`: `baseline-<timestamp>.json` history plus `latest*.json` per scope |
| `~/.vaso/backups/<timestamp>/` | File backups before `vaso fix` modifies anything |
| `~/.vaso/mcp-tool-baselines/` | Per-server tool-definition baselines for MCP-020 rug-pull detection (keyed by hostname + source) |
| `~/.vaso/plugins/` | User-plugin drop-in directory (`vaso ext`) |
| `~/.vaso/ioc/` | IOC feed cache + metadata fetched by `vaso update` |
| `~/.vaso/advisory/` | Advisory/CVE feed cache + metadata fetched by `vaso update` |
| `~/.vaso/probe/` | Downloaded `vaso-probe` binaries for remote scanning |
| `~/.vaso/mcp-state/` | Per-server MCP state: version history for MCP-027 rollback detection, config fingerprints for MCP-028 drift |
| `~/.vaso/mcp-pkg-cache/` | npm package tarballs downloaded by `vaso mcp scan --resolve-packages` |
| `~/.vaso/rules/` | Custom YAML rules (`vaso rules init`) |
| `~/.vaso/trusted-projects` | Projects whose `.vaso/rules/` load without `--project-rules` (one absolute path per line, owner-writable only) |

Nothing under `~/.vaso/` is sent anywhere. Reports go only where you write them (`-o`, `--output-dir`, stdout). VASO makes outbound network calls only in these cases:

- `vaso update` — fetches the signed IOC and advisory feeds (from `raw.githubusercontent.com` by default, or `--url` / `--advisory-url`)
- `vaso mcp scan --resolve-packages` (opt-in) — downloads npm package tarballs with `npm pack` from your configured npm registry for source analysis; they are never executed
- `vaso mcp scan --audit-deps` (opt-in) — sends the names and exact versions of MCP servers' npm and PyPI dependencies to OSV.dev (`api.osv.dev`; no code, paths or config)
- `--host` / `--inventory` remote scans — connect over SSH, copy the probe to each host, and, on first use without a local build, download the `vaso-probe` binary from GitHub Releases (SHA-256-verified, cached under `~/.vaso/probe/`)
- IOC-008 — whenever `VIRUSTOTAL_API_KEY` is set in VASO's environment, every `vaso scan` sends the SHA-256 hash of each skill file to VirusTotal (`www.virustotal.com`) with that key. Hashes only, never file content. Unset the variable to stop it

## Safety Guarantees

- VASO never executes scanned code: skill code, MCP server source and downloaded packages are analysed statically. It does run installed agent CLIs for read-only queries (version checks; OpenShell `sandbox list` / `policy get`)
- Nothing leaves the machine except in the cases listed under [Data Storage](#data-storage): feed updates, opt-in package and OSV lookups, remote scans and, when `VIRUSTOTAL_API_KEY` is set, file hashes sent to VirusTotal
- Remediation always creates backups before modifying files
- Only `vaso fix` changes agent files; scans write only VASO's own state under `~/.vaso/` and the reports you ask for
- User plugins are the exception to all of the above: they run as code with your rights (see [Plugins](#plugins-vaso-ext))

## Environment Variables

VASO itself reads:

| Variable | Effect |
|----------|--------|
| `VASO_CHECK_TIMEOUT` | Per-check timeout in seconds (1–86400; default 300). A check that runs longer is reported as errored and the scan exits `3` |
| `VIRUSTOTAL_API_KEY` | Enables IOC-008 (sends skill-file hashes to VirusTotal — see [Data Storage](#data-storage)) |

Agents can be moved off their default locations; VASO follows these variables when they are set in the environment it runs in. They apply to the user running VASO, not to other accounts scanned with `--all-users`:

| Agent | Variables |
|-------|-----------|
| Claude Code | `CLAUDE_CONFIG_DIR` (holds what `~/.claude` and `~/.claude.json` would) |
| Codex | `CODEX_HOME` (instead of `~/.codex`) |
| GitHub Copilot CLI | `COPILOT_HOME` (instead of `~/.copilot`) |
| Gemini CLI | `GEMINI_CLI_HOME` (`$GEMINI_CLI_HOME/.gemini`), `GEMINI_CLI_SYSTEM_SETTINGS_PATH`, `GEMINI_CLI_TRUSTED_FOLDERS_PATH` |
| Qwen Code | `QWEN_HOME` (instead of `~/.qwen`), `QWEN_CODE_SYSTEM_SETTINGS_PATH`, `QWEN_CODE_TRUSTED_FOLDERS_PATH` |
| Cursor | `CURSOR_CONFIG_DIR` (instead of `~/.cursor`) |
| OpenCode | `OPENCODE_CONFIG` (an extra config file), `OPENCODE_CONFIG_DIR` (an extra config directory), `OPENCODE_CONFIG_CONTENT`, `XDG_CONFIG_HOME`, `XDG_DATA_HOME` |
| Devin CLI | `XDG_CONFIG_HOME`, `XDG_DATA_HOME` |
| OpenClaw | `OPENCLAW_HOME` (replaces the home: `$OPENCLAW_HOME/.openclaw`), `OPENCLAW_STATE_DIR` (the state directory), `OPENCLAW_CONFIG_PATH` (the config file), `OPENCLAW_INCLUDE_ROOTS` |
| Hermes | `HERMES_HOME` (instead of `~/.hermes`), `HERMES_MANAGED_DIR` (instead of `/etc/hermes`) |
| PicoClaw | `PICOCLAW_HOME`, `PICOCLAW_CONFIG` |
| ZeroClaw | `ZEROCLAW_CONFIG_DIR`, `ZEROCLAW_DATA_DIR`, `ZEROCLAW_WORKSPACE` |
| IronClaw | `IRONCLAW_REBORN_HOME` (instead of `~/.ironclaw/reborn`) |
| Atomic Agent | `ATOMIC_AGENT_STATE_DIR` (instead of `~/.atomic-agent`) |
| NVIDIA OpenShell | `XDG_CONFIG_HOME`, `XDG_STATE_HOME`, `OPENSHELL_SANDBOX_POLICY` |
| Grok Bot | `SAND_DATA_ROOT`, `SAND_USER_DATA_DIR` |

`vaso mcp scan` follows `CLAUDE_CONFIG_DIR`, `CODEX_HOME`, `COPILOT_HOME` and `GEMINI_CLI_HOME` too. On remote scans the probe reports the variables as set on the host for the SSH session, with credential values redacted.

## Troubleshooting

**An agent isn't detected.** Run `vaso detect --verbose` (or `vaso detect -a <agent> --verbose`): it lists the paths VASO checked for each agent. If the agent keeps its config elsewhere, set the matching variable from [Environment Variables](#environment-variables) in the shell you run VASO from. A CLI agent is found through `PATH`, the usual install prefixes and Node version managers (nvm, fnm, asdf, mise, volta, n).

**A `CONFIG-LOAD` result.** VASO found a config file it couldn't read or parse (permission denied, malformed JSON/YAML/TOML, an unreadable config directory, or a file inside a credential store). It is a `warning` finding with the file and the reason; fix the file (or its permissions) and re-scan. It doesn't make the scan incomplete — see [Exit Codes](#exit-codes).

**"IOC feed is stale" / "Advisory feed is stale".** A feed fetched earlier by `vaso update` is more than 7 days old. Run `vaso update`. Installs that never ran `vaso update` use the bundled data and don't show the warning.

**Exit code 3.** A check or adapter errored (threw, or ran past the per-check timeout), a custom rule ran out of matching time, or a remote host wasn't scanned. The report lists the errored results; findings may be missing. Raise the timeout with `VASO_CHECK_TIMEOUT=<seconds>` if a check is merely slow on a large install.

**An error message without detail.** Run the command again with `--debug` (`vaso --debug scan …`) for the full stack trace.

**A custom rule or plugin doesn't load.** `vaso rules list` and `vaso rules validate <file>` show why a rule is skipped (often the file or `~/.vaso/rules/` being writable by group or others); `vaso ext list` shows a plugin's load error.

**Remote scan problems** (SSH failures, probe download, limited coverage): see [Troubleshooting](network-scanning-guide.md#troubleshooting) in the network scanning guide.

## Uninstall

```bash
npm uninstall -g vaso      # add sudo if you installed with sudo
```

Then remove VASO's state if you no longer need it. `~/.vaso/backups/` holds the backups `vaso fix --rollback` restores from — keep it until you are sure you won't roll back:

```bash
rm -rf ~/.vaso
```

Remove a project's `.vaso/rules/` separately if you created one. VASO installs no services, cron jobs or shell hooks.
