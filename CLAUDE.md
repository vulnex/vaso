# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

VASO (VULNEX Agent Security Observer) is an agent-agnostic security scanner for AI agent deployments. It supports six agent frameworks (OpenClaw, NanoClaw, PicoClaw, IronClaw, Nanobot, ZeroClaw) plus MCP server security scanning. 106 security checks across 10 categories, with auto-remediation, baseline diffing, and plugin extensibility.

**Version:** 0.1.0
**Status:** Implemented through Phase 0.6. Phases 0.1–0.6 complete; Phase 0.7 (AI/dashboard) not started.
**Design document:** `devnotes/vaso-design-document.md`

## Build Commands

```bash
npm install                # Install dependencies
npm run build              # Build with tsup → dist/cli.js (ESM)
npm run dev                # Build in watch mode
npm test                   # Run unit tests (vitest, src/**/*.test.ts)
npm run test:e2e           # Run E2E tests (fixture-based, no Docker)
npm run test:integration   # Run integration tests (Docker required)
npm run test:all           # Run all three test suites sequentially
npm run lint               # Type-check with tsc --noEmit
```

## Technology Stack

- **Runtime:** Node.js 18+
- **Language:** TypeScript 5.x (strict mode, ES2022 target, ESM)
- **Build:** tsup (ESM output with Node.js shebang)
- **CLI:** commander + chalk
- **Config parsing:** yaml + smol-toml + native JSON
- **AST analysis:** @babel/parser + @babel/traverse
- **Testing:** vitest (unit) + vitest + testcontainers (integration) + vitest (E2E)

## Architecture

### Entry Points

- `src/cli.ts` — Commander.js CLI setup, adapter/check registration, user plugin loading
- `bin/vaso` — Node.js shim that loads `dist/cli.js`
- `bin/vaso-quick.sh` — Zero-dependency Bash quick-scan (5 critical checks, no Node.js required)

### Core Types (`src/core/types.ts`)

- `AgentType` — `'openclaw' | 'nanoclaw' | 'picoclaw' | 'ironclaw' | 'nanobot' | 'zeroclaw' | 'mcp' | 'skill-audit'`
- `CheckCategory` — `'config' | 'skills' | 'ioc' | 'network' | 'runtime' | 'policy' | 'mcp' | 'ironclaw' | 'nanobot' | 'zeroclaw'`
- `OutputFormat` — `'terminal' | 'json' | 'sarif' | 'markdown' | 'html'`
- `CheckModule` — `{ id, name, category, severity, description, run(context), fix?(context) }`
- `ScanContext` — `{ installation, configs, platform, skillFiles?, mcpConfigs? }`
- `CheckResult` — `{ id, name, category, severity, passed, message, evidence?, fixable? }`

### Agent Adapter System

The `AgentAdapter` interface (`src/adapters/adapter.ts`) is the central abstraction. Each adapter implements `detect()`, `getConfigPaths()`, `getSkillsDir()`, and `getGatewayInfo()`. All check modules operate through `ScanContext` provided by adapters.

Six adapters registered in `src/cli.ts` via `adapterRegistry`:

| Adapter | File | Config Formats | Features |
|---------|------|----------------|----------|
| OpenClaw | `src/adapters/openclaw.ts` | JSON, YAML | Sub-agent configs, multi-user, profile support, macOS .app detection |
| NanoClaw | `src/adapters/nanoclaw.ts` | JSON, ENV | Profile support |
| PicoClaw | `src/adapters/picoclaw.ts` | JSON | Minimal config |
| IronClaw | `src/adapters/ironclaw.ts` | TOML | Rust framework, gRPC gateway |
| Nanobot | `src/adapters/nanobot.ts` | JSON | Discord/Slack bot framework |
| ZeroClaw | `src/adapters/zeroclaw.ts` | TOML | Rust framework, Composio integration |

### Check Module System

106 checks across 10 categories under `src/checks/`:

| Category | Directory | Count | Scope |
|----------|-----------|-------|-------|
| config | `src/checks/config/` | 15 (CFG-001–015) | Gateway binding, API keys, TLS, permissions, sandbox, auth |
| skills | `src/checks/skills/` | 12 (SKL-001–012) | AST-based data flow, eval/exec, obfuscation, exfiltration |
| ioc | `src/checks/ioc/` | 8 (IOC-001–008) | C2 IPs, malicious domains, typosquatting, file hashes |
| network | `src/checks/network/` | 5 (NET-001–005) | Gateway exposure, WebSocket origin, port scan |
| runtime | `src/checks/runtime/` | 5 (RUN-001–005) | LaunchAgents, cron, Docker hardening, process ancestry |
| policy | `src/checks/policy/` | 5 (POL-001–005) | Tool exec approval, log redaction, credential permissions |
| mcp | `src/checks/mcp/` | 18 (MCP-001–018) | OAuth 2.1 security, transport, tool authorization, prompt injection |
| ironclaw | `src/checks/ironclaw/` | 12 (IC-001–012) | IronClaw-specific: webhook bind, sandbox, auto-approve tools |
| nanobot | `src/checks/nanobot/` | 12 (NB-001–012) | Nanobot-specific: channel allow, shell filtering, memory injection |
| zeroclaw | `src/checks/zeroclaw/` | 14 (ZC-001–014) | ZeroClaw-specific: API keys, autonomy mode, filesystem access |

All checks registered via `src/checks/index.ts` → `registerAllChecks()`.

### Scan Engine Flow (`src/core/engine.ts`)

1. Auto-detect installed agents via adapter registry
2. Load and parse configs per agent (YAML/JSON/TOML/ENV via `src/core/config-loader.ts`)
3. Register applicable check modules (filtered by agent type and platform)
4. Run checks concurrently
5. Collect results, compute score 0–100 with letter grade A–F (`src/core/scoring.ts`)
6. Output in chosen format via reporters (`src/reporting/`)

### Key Directories

```
src/
├── cli.ts                 # CLI entry point, adapter/check registration
├── core/                  # Engine, types, scoring, config-loader, baseline, patterns, utils
├── adapters/              # 6 agent adapters + adapter interface + registry
├── checks/                # 106 checks in 10 category subdirectories
├── analyzers/             # AST analyzer, pattern engine, entropy analyzer
├── ioc/                   # IOC database, Ed25519-signed updater, typosquat detection
├── remediation/           # Fix engine, config writers (JSON/YAML/TOML/ENV), rollback
├── reporting/             # 5 formatters: terminal, json, sarif, markdown, html
├── commands/              # CLI command handlers: scan, detect, fix, mcp, skill-audit, update, plugin, user-plugin
├── plugins/               # Agent plugin system (standalone CLI + before_agent_start hook mode)
├── user-plugins/          # Drop-in user plugin loader (~/.vaso/plugins/)
└── mcp/                   # MCP config discovery (Claude Desktop, Cursor, VS Code, project mcp.json)
```

### Analyzers (`src/analyzers/`)

- `ast-analyzer.ts` — Babel AST parsing for skill code: data-flow tracing, eval/exec, network calls, FS access
- `pattern-engine.ts` — Regex pattern matching with compilation caching, obfuscation detection
- `entropy.ts` — Shannon entropy analysis for detecting high-entropy strings (API keys, secrets)

### IOC System (`src/ioc/`)

- `database.ts` — In-memory IOC storage with bundled C2 IPs, domains, hashes, publisher lists
- `updater.ts` — Remote feed fetcher with Ed25519 signature verification and version monotonicity
- `typosquat.ts` — Levenshtein distance for package name typosquatting detection
- `feed-types.ts` — Feed data types; `public-key.ts` — Pinned Ed25519 key

### Remediation (`src/remediation/`)

- `engine.ts` — Fix orchestrator with interactive prompts, dry-run, backup before changes
- `config-writer.ts` — Format-aware config updaters (JSON, YAML, TOML, ENV)
- `prompt.ts` — TUI yes/no/all/quit prompts via node:readline
- `rollback.ts` — Restore from `~/.vaso/backups/` by timestamp

42 automatable fixes + guidance-only responses for manual fixes.

### Reporting (`src/reporting/`)

5 output formats: terminal (color-coded), JSON, SARIF (GitHub Code Scanning), Markdown, HTML (self-contained, XSS-safe).

### Plugin System (`src/plugins/`)

Dual-mode: standalone CLI and agent framework plugin (hooks into `before_agent_start`). Plugin installer generates framework-specific files for OpenClaw, NanoClaw, PicoClaw.

### User Plugins (`src/user-plugins/`)

Drop-in `.js`/`.mjs` files in `~/.vaso/plugins/`. Register custom checks, adapters, or reporters. Error isolation prevents crashes. Example plugins in `examples/plugins/`.

## CLI Commands

```bash
vaso scan [-a agent] [-f format] [-o file] [--save-baseline] [--diff] [--all-users]
vaso detect [-a agent] [-f format] [--all-users] [--verbose]
vaso fix [-a agent] [--dry-run] [-y] [--rollback]
vaso update [--url <url>] [--force]
vaso mcp scan [-f format] [-o file] [-p paths...]
vaso mcp list [-f format] [-p paths...]
vaso skill audit <path> [-f format] [-o file]
vaso plugin install -a <agent> [--force]
vaso plugin uninstall -a <agent>
vaso plugin status [-a agent] [-f format]
vaso ext list [-f format]
vaso ext info <name> [-f format]
```

## Key Design Decisions

- **AST over regex:** Skill code analysis uses @babel/parser for data-flow tracing (source→sink), not string matching
- **Differential scanning:** Stores historical baselines (`src/core/baseline.ts`) to detect config regressions
- **No eval/exec:** VASO never executes scanned code — all analysis is purely static
- **No data exfiltration:** Nothing leaves the machine unless the user explicitly opts in
- **Signed IOC updates:** Ed25519-signed threat feeds to prevent tampered IOC injection
- **Dual mode:** Ships as both standalone CLI and agent plugin (hooks into `before_agent_start`)
- **Offline-first:** Bundled IOC data always available; remote feeds are optional

## Testing

- **Unit tests** (`src/**/*.test.ts`): ~474 tests covering core, adapters, checks, analyzers, IOC, reporting, remediation, plugins
- **E2E tests** (`testing/e2e/`): 34 tests against temp fixture directories, includes real MCP server packages
- **Integration tests** (`testing/integration/`): ~100 Docker-based tests with real agent containers via testcontainers
- **Test configs:** `vitest.config.ts` (unit), `testing/vitest.config.e2e.ts`, `testing/vitest.config.integration.ts`

## Not Yet Implemented

- AI-powered analysis (ONNX prompt injection classifier — Phase 0.7)
- Interactive web dashboard (Phase 0.7)
- Single-binary distribution (pkg)
- Custom scoring weights (currently fixed: critical -12, warning -5, info -1)
