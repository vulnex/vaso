# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

VASO (VULNEX Agent Security Observer) is an agent-agnostic security scanner for AI agent deployments (OpenClaw, NanoClaw, PicoClaw, and future frameworks). It consolidates capabilities from five existing OpenClaw-specific tools into a unified TypeScript/Node.js CLI scanner with 45+ security checks.

**Status:** Pre-implementation (design document only at `devnotes/vaso-design-document.md`). No source code exists yet.

## Planned Build Commands

```bash
npm install              # Install dependencies
npm run build            # Build with tsup or esbuild
npm test                 # Run tests with vitest
npx vitest run <file>    # Run a single test file
```

## Technology Stack

- **Runtime:** Node.js 18+
- **Language:** TypeScript 5.x
- **Build:** tsup or esbuild
- **CLI:** commander + chalk
- **Config parsing:** yaml (npm) + native JSON
- **AST analysis:** @babel/parser + @babel/traverse
- **Testing:** vitest
- **Optional:** Semgrep integration, onnxruntime-node (ML), pkg (single binary)

## Architecture

### Agent Adapter System (Core Abstraction)

The `AgentAdapter` interface is the central design pattern. Each supported agent framework (OpenClaw, NanoClaw, PicoClaw) has an adapter that knows how to discover installations, locate config files, find skills directories, and expose gateway/credential info. All check modules operate through this adapter interface, making them agent-agnostic.

Key interfaces: `AgentAdapter`, `AgentInstallation`, `CheckModule`, `ScanContext`, `CheckResult` — all defined in the design document section 5.

### Check Module System

45+ checks organized into six categories under `src/checks/`:
- **config/** — 15 configuration auditing checks (gateway binding, API key exposure, TLS, permissions, etc.)
- **skills/** — 12 skill code analysis checks (AST-based data flow, obfuscation, dependency audit)
- **ioc/** — 8 IOC matching checks (C2 IPs, malicious domains, typosquatting via Levenshtein distance)
- **network/** — 5 network exposure checks (gateway exposure, WebSocket origin validation)
- **runtime/** — 5 process/persistence checks (LaunchAgents, cron, Docker)
- **policy/** — 5 compliance checks (DM/tool/sandbox policies)

Each check implements `CheckModule` with a `run(context: ScanContext)` method and optional `fix()` for remediation.

### Scan Engine Flow

1. Auto-detect installed agents via adapter registry
2. Load and parse configs per agent (proper YAML/JSON parsing, not grep)
3. Register applicable check modules
4. Run checks concurrently
5. Collect results, compute score (0-100, letter grade A-F)
6. Output in chosen format (terminal, JSON, SARIF, HTML, markdown)

### Key Directories

- `src/adapters/` — Agent framework adapters + registry
- `src/core/` — Scan engine, config loader, check registry, shared types
- `src/checks/` — Individual check modules (six subdirectories)
- `src/analyzers/` — AST analyzer, pattern engine, Semgrep runner, AI analyzer
- `src/ioc/` — IOC database manager and auto-updater
- `src/remediation/` — Fix engine and per-check fix actions
- `src/reporting/` — Output formatters (terminal, JSON, SARIF, HTML, markdown)
- `src/plugins/` — Agent plugin integrations (OpenClaw, NanoClaw, PicoClaw)
- `bin/vaso` — CLI entry point; `bin/vaso-quick.sh` — zero-dependency Bash quick-scan

## Key Design Decisions

- **AST over regex:** Skill code analysis uses @babel/parser for data-flow tracing (source→sink), not string matching. This is the primary quality differentiator over existing tools.
- **Differential scanning:** Stores historical baselines to detect gradual supply chain attacks and config regressions.
- **Offline-first AI:** Bundles ONNX prompt injection classifier (~50MB) for local inference; API analysis is opt-in only.
- **No eval/exec:** VASO never executes scanned code — all analysis is purely static.
- **No data exfiltration:** Nothing leaves the machine unless the user explicitly opts in.
- **Signed IOC updates:** Ed25519-signed threat feeds to prevent tampered IOC injection.
- **Dual mode:** Ships as both standalone CLI and agent plugin (hooks into `before_agent_start`).

## Development Phases

Phase 0.1 (foundation): CLI scaffold, adapter interface, OpenClaw adapter, 15 config checks, terminal + JSON output. Phase 0.2: AST analyzer, skill checks. Phase 0.3: IOC database. Phase 0.4: Remediation. Phase 0.5: Network/runtime. Phase 0.6: Multi-agent adapters, SARIF, plugin mode. Phase 0.7: AI + dashboard. Phase 1.0: Release.
