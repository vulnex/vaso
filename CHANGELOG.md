# Changelog

All notable changes to VASO (VULNEX Agent Security Observer) will be documented in this file.

This project adheres to [Semantic Versioning](https://semver.org/).

## [0.4.2] - 2026-05-12

### Changed

- **Install path moved from the npm registry to a GitHub source install.** The package name `vaso` on npm is squatted by an unrelated React library; users following the old `npm install -g vaso` instructions were silently installing that package instead of VASO. All install paths now point at `github:vulnex/vaso#<ref>`:
  - `install.sh` no longer calls `npm install -g vaso`. New `resolve_version()` helper picks the install ref in this order: (1) `VASO_VERSION` env override, (2) the latest tag returned by `GET /repos/vulnex/vaso/releases/latest`, (3) a hardcoded `FALLBACK_VERSION` (`v0.4.2`) if the API call fails. The install command is now `npm install -g "github:vulnex/vaso#<ref>"`. `MIN_NODE_MAJOR` also bumped from 18 to 20 to match `package.json` engines and the rest of the docs.
  - `action.yml` (the official GitHub Action) installs via `github:vulnex/vaso#<ref>`. The `version` input is now a git ref (tag/branch/SHA) rather than an npm dist-tag; default changed from `latest` to `v0.4.2`.
  - `README.md` and `doc/user-guide.md` install sections rewritten to lead with the `curl | bash` one-liner and the `github:vulnex/vaso#v0.4.2` npm form, plus a short note that the bare `vaso` name on npm is unrelated.
- **`package.json` swaps `prepublishOnly` for `prepare`.** Git installs (`npm install -g github:vulnex/vaso#<ref>`) require a build step *during* install, which `prepublishOnly` doesn't trigger. `prepare` covers both publish and git-install paths; the build is identical (`npm run build` → tsup → `dist/cli.js`).

## [0.4.1] - 2026-05-11

### Added

- **Two new desktop-app adapters with 16 security checks** (`CD-001`–`CD-010`, `CG-001`–`CG-006`). Brings VASO to **18 adapters** and **251 total checks** across **16 categories**. The desktop apps are distinct from the existing `claude-code` CLI adapter — they target the standalone Claude Cowork / ChatGPT desktop applications, which have their own MCP surface, code-signing posture, and on-disk state.

  - **Claude Desktop adapter** (`src/adapters/claude-desktop.ts`): detects the Claude Cowork host application on macOS (`~/Library/Application Support/Claude/claude_desktop_config.json`) and Windows (`%APPDATA%\Claude\claude_desktop_config.json`); no Linux build exists. MCPB Desktop Extensions under `Claude Extensions/` are inventoried and signature-verified. Version derived from `CFBundleShortVersionString` in the `.app`'s `Info.plist`. Active model surfaced from the Chromium Local Storage leveldb (`<installDir>/Local Storage/leveldb/`) — the picker writes the selected model id to a `model-selector-local_<account>` anchor key; the adapter scans `.ldb`/`.log` files as a byte stream, finds the anchor, and extracts the model id from the following window. Surfaced as `via: 'cowork local-storage'` in `vaso detect`.

  - **ChatGPT Desktop adapter** (`src/adapters/chatgpt-desktop.ts`): macOS-only, detects `/Applications/ChatGPT.app` plus `~/Library/Application Support/com.openai.chat/`. Reads binary plists in `~/Library/Preferences/com.openai.chat*.plist` via the `plist` npm package (added as a runtime dep — `plutil -convert json` refuses to render NSDate/NSData-bearing plists). Paired connectors enumerated under `app_pairing_extensions/`. Version + bundle signature pulled via `defaults` / `codesign` against the OpenAI Team ID (`2DC432GLL2`).

  - **Claude Desktop checks** (`src/checks/claude-desktop/`, 10 checks):
    - **CD-001** (critical): plaintext API key in `mcpServers.*.env.*`
    - **CD-002** (critical): config file world-readable when env values are present
    - **CD-003** (warning): unpinned MCP server package (npx/pnpm/yarn/bunx/uvx/pipx without `@version` or `@sha256:`)
    - **CD-004** (warning): MCP server URL over plaintext `http://`
    - **CD-005** (warning): unsigned MCPB Desktop Extension under `Claude Extensions/`
    - **CD-006** (critical): `alwaysApprove` / `autoApprove` auto-trust on MCP server
    - **CD-007** (warning): sensitive-path filesystem-server scope (`~/.ssh`, `~/.aws`, `/`, etc.)
    - **CD-008** (warning): stdio MCP server invoked via shell `-c`
    - **CD-009** (warning): world-writable MCP command path
    - **CD-010** (critical): credentials embedded directly in MCP URL or headers

  - **ChatGPT Desktop checks** (`src/checks/chatgpt-desktop/`, 6 checks):
    - **CG-001** (warning): conversation / draft `.data` files world-readable
    - **CG-002** (warning): plaintext `userEmail` in `StatsigService.plist` (masked in evidence)
    - **CG-003** (info): training-data opt-in active
    - **CG-004** (info): precise-location opt-in active
    - **CG-005** (critical): `codesign` / Team-ID mismatch on `/Applications/ChatGPT.app` (expected `2DC432GLL2`)
    - **CG-006** (info): inventory of paired connectors in `app_pairing_extensions/`

- **Snapshot/SSH transport coverage for the new desktop adapters.** The probe `allowlist.go` now permits `defaults`, `codesign`, and `plutil` (all stock Apple binaries, used read-only here for `Info.plist` reads, bundle signature verification, and plist format conversion). A new `expandArgsPerUser` helper in `probe/collector.go` fans out `~/`-prefixed command args across each discovered user, mirroring the existing per-user expansion for `filePaths`/`globPatterns`/`directoryListings`. ChatGPT Desktop's `loadPlistAsObject` now calls `fs.exec('plutil', ['-convert', 'xml1', '-o', '-', filePath])` unconditionally, so CG-002/003/004 produce identical FAIL/PASS verdicts over snapshot transport as they do locally — previously they silently passed remote even when the underlying conditions held, which was a false-negative gap. Claude Desktop's leveldb model walker also flows through `ctx.fs.readFile()` so the ASCII model-anchor extraction survives the probe's UTF-8 wire format.

- **Multi-host scanning ergonomics**: `vaso scan` and `vaso detect` gain three flags that make fleet-style runs practical:
  - `--parallel <n>` — caps concurrent SSH targets (default 5). Replaces the previously hard-coded `CONCURRENCY=5` in `src/transport/multi-host.ts` and `src/commands/detect.ts`. Validated as a non-negative integer; `--parallel 0` is rejected with exit 2.
  - `--ssh-retries <n>` — additional SSH attempts after the first failure (default 0, so existing behavior is preserved). Exponential backoff `1s → 2s → 4s`, capped at 8s. Each retry uses a fresh probe-binary UUID so it cannot collide with a half-cleaned-up previous attempt; cleanup of `/tmp/vaso-probe-<uuid>` and `/tmp/vaso-manifest-<uuid>` remains in `executeRemoteProbe`'s `finally` block. A retry banner (`Retry N/M for <host>: <reason>`) is printed before each new attempt.
  - `--save-snapshot <dir>` on `vaso scan` — already existed on `vaso detect`. Writes each host's collected `ProbeSnapshot` to `<dir>/<safe-hostname>.json` before the local scan engine runs against it. Lets users fan out once over SSH and re-scan offline against new baselines / new rule sets without re-paying the SSH round-trip.
- **Live per-host progress for fleet scans**: `vaso scan` and `vaso detect` now print one line per host as it completes (`✓ label (Xms) — score N/100, AC / BW / CI` for scan, `✓ label (Xms) — N agent(s) detected` for detect, `✗ label (Xms): error` on failure). A slow host no longer blanks the terminal until the rest of the fleet finishes.
- **`--silent` flag** on `vaso scan` and `vaso detect`: suppresses all stdout/stderr chatter — banner, retry banners, save-snapshot lines, per-host progress, summary, and the "Report written to" notice. Requires `-o` or `--output-dir` (the CLI rejects `--silent` without an output destination with exit 2). Errors and validation failures still print to stderr. Useful for cron / CI / scripted runs.
- **`--output-dir <dir>` on `vaso scan`**: writes one report per host as `<dir>/<safe-hostname>.<ext>` using the format's natural extension (`json`, `sarif`, `md`, `html`, `csv`, `xml` for JUnit, `txt` for terminal). The directory is created if it doesn't exist. Mutually exclusive with `-o`.
- **`--output-dir <dir>` on `vaso detect`** (mirror of the `vaso scan` flag): writes one file per host as `<dir>/<safe-hostname>.<ext>` (`.json` for JSON format, `.txt` for terminal). Mutually exclusive with `-o`. Useful for fleet-detect runs where you want a separate file per host.

### Changed

- **Multi-host orchestrator now uses a true worker pool** instead of wave batching (`src/transport/multi-host.ts`). The previous `for (i += CONCURRENCY)` loop made a slow host in batch *N* block faster hosts queued in batch *N+1*; the new `runConcurrent<T, R>` helper launches a fresh task as soon as a slot opens up. Same exported API.
- **`scanMultipleHosts` API extended** with `concurrency`, `retries`, and three callbacks: `onSnapshot(target, snapshot)` (invoked once a snapshot is collected, before scanning), `onRetry(target, attempt, err)` (invoked before each retry's sleep returns), and `onComplete(entry)` (invoked after each host finishes, success or failure — the seam used by live progress and per-host file output). All optional; defaults preserve previous behavior.
- **`vaso detect` now uses the shared transport layer.** Its inline concurrency loop and direct `executeRemoteProbe` call were replaced with `runConcurrent` + `executeRemoteProbeWithRetry` from `src/transport/`, eliminating duplicated logic between `scan` and `detect`.
- **Generic retry helper** `withRetry<T>({ retries, fn, onRetry?, sleep? })` extracted from `executeRemoteProbeWithRetry` (`src/transport/ssh.ts`). The optional `sleep` injection seam keeps unit tests fast without faking timers.
- **`-o file.sarif` / `-o file.xml` (with `-f junit`) on multi-host scans is now rejected** with exit 2 and a clear pointer to `--output-dir`. The previous text-concatenation produced invalid SARIF and invalid JUnit XML — the formats can't be safely glued together as text. Single-host scans, and other formats (`json` aggregates, `md` / `html` / `csv` / `terminal` text-concat) are unchanged.
- **Snapshot warnings now respect `--silent`** in `vaso scan`. When scanning a non-root snapshot or echoing the source host name, those informational lines are suppressed if `--silent` is set.

- **Check correctness sweep against `docs/checks-validation.md`.** A multi-commit pass over the regex- and AST-based checks the validation report flagged as heuristic. User-visible effect: fewer false positives without changing what real issues get flagged. Where the sweep removes findings, fleet operators comparing against a v0.4.0 baseline may see counts drop — those are points highlighted below.
  - **`CFG-003` (config file permissions) and `POL-003` (session credentials) narrowed to adapter-declared credential paths** via a new `getCredentialPaths()` adapter hook and `ScanContext.credentialPaths`. Previously CFG-003 flagged every parsed config with group/world bits set and POL-003 walked the entire install dir matching filenames against `session|token|credential|auth|.secret_key` — both fired on benign docs, fixtures, and helpers. **REDUCES findings on existing scans.**
  - **`CFG-002` evidence redaction.** API-key snippets in evidence are now redacted to `prefix...suffix` instead of carrying the full token into the report. Also bumped fixed-length token quantifiers (`ghp_`/`gho_`/`AKIA`/Telegram) from `{N}` to `{N,}` so longer-than-spec tokens redact in full instead of either leaking bridging bytes (unanchored patterns) or failing to match entirely (Telegram's `\b`-anchored pattern, which used to leak the whole token).
  - **IOC IP and domain matching** (`IOC-001`, `IOC-002`) now use address/hostname boundaries instead of `String.includes()`. A flagged IP `185.199.228.220` no longer matches `1185.199.228.2200`; a flagged domain `evil.com` no longer matches `notevil.com` or `evil.community.io`.
  - **`MCP-019` (toxic tool flow)** bounds each tool's source/sink slice at the next `server.tool()` / `server.registerTool()` call site, so adjacent tool definitions can't smear each other's capability classification.
  - **MCP OAuth checks (`MCP-013`, `MCP-014`, `MCP-015`, `MCP-018`) plus `MCP-005` (tool injection) and `MCP-007` (prompt injection via tool results)** now skip `//` and `*` lines so OAuth-pattern strings in line comments, JSDoc, or inline anti-pattern documentation no longer trip the checks.
  - **Skill pattern checks (`SKL-004`, `SKL-005`, `SKL-006`, `SKL-009`)** inherit comment-skipping from the underlying `scanWithPatterns` engine. `#` is intentionally *not* skipped because `SKL-007` and `CC-011` scan markdown content where headings carry meaning.
  - **`IOC-007` (binary pattern match) anchors executable magic-byte patterns at file offset 0.** Previously the 2-byte PE/DOS magic `MZ` was latin1-decoded and substring-searched across UTF-8-decoded text, so any source file containing the substring `"MZ"` (e.g. identifiers like `xMZx` or constants like `MZmax`) tripped the check. Magic-byte patterns now match only at offset 0 against raw bytes; regex patterns (NUL-padding, packed JS eval wrapper) continue to operate on text.

- **`FSProvider.readBytes(path): Promise<Uint8Array>`** added so callers that need byte-level semantics no longer go through UTF-8 decoding. `LocalFSProvider` returns the Node `Buffer` (Buffer subclasses `Uint8Array`); `SnapshotFSProvider` re-encodes the stored UTF-8 text — best-effort, since any bytes the probe couldn't represent as valid UTF-8 were replaced with U+FFFD before reaching the snapshot. ASCII-safe magics (ELF, `MZ`) roundtrip; truly binary magics (Mach-O `0xcffaedfe`) are lossy in snapshot mode.

- **`MCP-020` tool-rug-pull baseline storage is now injectable** via `ScanContext.mcpToolBaselineStore`. Baseline keys also include the source `localPath`/`packageName` so two MCP servers with the same `serverName` but different sources don't collide. Tests can supply an in-memory store instead of writing to `~/.vaso/mcp-tool-baselines/`.

- **Skill-file discovery centralized in the scan engine.** Each skill / IOC check used to call `getSkillFiles(skillsDir)` independently, falling back to a `LocalFSProvider` and producing inconsistent results under snapshot/remote scans. The engine now pre-populates `ScanContext.skillFiles` once via the active `ctx.fs`, and every skill / IOC check reads from there.

- **`ScanContext.fs` is the canonical source of host state for checks.** Modules that previously read `os.homedir()`, `process.env`, or `process.cwd()` directly now go through `ctx.fs.homedir()` and `ctx.fs.getEnv()`, so snapshot- and SSH-mode scans see the target host's state instead of the scanner's. Concretely: `cc-009-sensitive-additional-dirs`, `cd-007-filesystem-server-scope`, `cdx-006-trusted-projects-scope`, `pol-001-exec-approval`, `oc-004-openclaw-home-redirect`, and `nc-003-nanoclaw-home-redirect`.

- **`FSProvider.hostname(): string` promoted to a real interface method.** Previously SnapshotFSProvider exposed a snapshot-specific `get hostname()` accessor and LocalFSProvider had no equivalent. The new interface method makes hostname routable through `ctx.fs` the same way `homedir()` and `getEnv()` already are. `LocalFSProvider` returns `os.hostname()`; `SnapshotFSProvider` returns the value the Go probe collected. The two pre-existing callers of the property-style accessor (`vaso scan` setting `result.host` on snapshot scans and the snapshot-fs-provider unit test) updated to method-call form.

- **`MCP-020` (tool definition rug pull) baseline keys now mix hostname into the hash.** Previously `baselineKey(source)` derived its identity from `localPath ?? packageName ?? serverName`. For fleet scans where two hosts share an MCP config block — a server named `"fs"` launched via shell without a `localPath` or `packageName` — both hosts fell back to the bare serverName and collided onto the same baseline file. The second host's *first* scan then looked like a rug pull on top of the first host's already-seeded baseline. `baselineKey()` and `diffToolBaseline()` gained an optional `hostname` parameter; MCP-020 passes `ctx.fs.hostname()`. `undefined` hostname is treated as a stable default so any external caller (and the existing tool-baseline tests that don't simulate fleet scans) keeps the same key.

- **`installation.skillsDirs` (plural) now drives skill-file enumeration.** OpenClaw per-agent installations declare two locations on `AgentInstallation`: the shared `~/.openclaw/skills` directory and the per-agent `~/.openclaw/agents/<name>/skills` directory. The adapter populated both — `skillsDirs` holding the full list and `skillsDir` set to the per-agent entry for backward compatibility — but the scan engine and the IOC-001 / IOC-002 directory scanners only consulted the singular field. Skills installed under the shared location silently bypassed `SKL-001..012`, `IOC-003..008`, and `IOC-001`/`IOC-002`. New `getAllSkillsDirs(installation)` helper in `core/utils.ts` returns the plural list when present and falls back to `[skillsDir]`; the engine flat-maps `getSkillFiles()` over every dir to populate `ctx.skillFiles`, and IOC-001/002 use the same helper for their scan-dir list.

- **Adapter, check, and remediation-backup errors are now surfaced instead of silently dropped.** A multi-touch sweep over the scan pipeline:
  - Adapter detection failures become `ADAPTER-DETECT` warning findings via a new `AdapterRegistry.detectAllDetailed()`; the previous `detectAll()` is kept as a back-compat wrapper that throws away the error metadata.
  - Per-check `Promise` rejections in `scan`, `scanMCP`, and `scanSkillAudit` are now reported as warning findings instead of being filtered out of the result.
  - Baseline diff key now includes `user/profile/agentName/installDir` plus sorted evidence, so the same check ID across two installations no longer collapses into a single baseline row.
  - Remediation no longer swallows backup failures — the fix aborts and the user is told.
  - `ScanEngine` filters checks by `this.fs.platform` instead of the host's `process.platform`, so snapshot/SSH scans see the scanned host's platform.
  - `AGENT_TYPES` / `CHECK_CATEGORIES` runtime arrays moved into `core/types.ts` so the parked `rules/schema.ts` work can't drift from the union types.

### Fixed

- **`--silent` actually silent now.** The CLI banner and IOC/advisory feed warnings were printed by the `preAction` hook *before* the action handler saw `--silent`. The hook was also reading `thisCommand.opts()` (the program's options, always empty) instead of `actionCommand.opts()` (the subcommand's options, where `--silent` lives), so the silent gate never fired. Both fixed: hook now reads from `actionCommand` and skips the banner / plugin warnings / rules warnings / stale-feed warnings when `--silent` is set.
- **`--silent` validation is now consistent across all scan/detect modes.** Previously only the SSH branch enforced "—silent requires `-o` or `--output-dir`"; the local and snapshot paths silently ignored a misuse. Both validations are now hoisted to the top of `runScan` / `runDetect`, so `vaso detect --silent` (no output destination) exits 2 with a clear error regardless of which scan mode would have been taken.
- **`-o <path>` now creates missing parent directories.** Passing `-o reports/run-1/file.json` previously failed with `ENOENT` if `reports/run-1/` didn't exist. New `writeFileEnsureDir` helper in `src/core/utils.ts` does `mkdir -p $(dirname path)` before writing. Wired into both `vaso scan` and `vaso detect`.

- **Phantom coding-agent installations no longer registered from unrelated tools.** A bare `~/.copilot/`, `~/.cursor/`, `~/.codex/`, `~/.qwen/`, `~/.gemini/`, `~/.claude/`, or `~/.opencode/` directory — without any recognized config files and without a CLI binary on `PATH` — used to be registered as an installation, producing phantom `vaso detect` rows with `Config files: 0` and `Version: unknown`. The Copilot IDE extension and `gh copilot` write under `~/.copilot/ide/`; `~/.cursor/` is the Cursor IDE's config dir; the others get auto-created by unrelated tooling. All seven coding-agent adapters now require at least one recognized config file or a confirmed CLI binary before registering. One regression test per adapter.

### Tests

- `runConcurrent`: 5 new tests (input-order preservation when items finish out of order, concurrency cap honored, oversized concurrency, empty input, clamp ≤1 to a single worker).
- `withRetry`: 5 new tests (success on first try, retry-then-succeed with `onRetry` invocation order, exhaustion throws final error, `retries: 0` short-circuits, sleep is called with `attempt` number).
- `scanMultipleHosts.onComplete`: fires for every host with target / error / durationMs.
- `vaso scan` validation: 8 new tests covering invalid `--parallel` (non-numeric, zero), negative `--ssh-retries`, `-o` + `--output-dir` mutex, `--silent` without an output destination (multi-host and local), `-o file.sarif` rejected for multi-host, `-o file.xml` rejected for multi-host JUnit, plus a positive test that `--silent + -o` suppresses the "Report written" message.
- `vaso scan` `-o` auto-mkdir: 1 new test confirming `mkdir(parentDir, { recursive: true })` is called before `writeFile`.
- `vaso detect` validation: 2 new tests (`--silent` without output destination rejected, `-o + --output-dir` mutex).
- `writeFileEnsureDir`: 4 new tests in `src/core/utils.test.ts` (existing parent, missing nested parents, overwrite, bare filename).
- **Check-correctness sweep added ~170 unit tests across the heuristic checks (`scanWithPatterns`, MCP OAuth/tool-injection/prompt-injection, skill AST/pattern, IOC-001/002/007, CFG-002/003, POL-003).** Tests include explicit false-positive fixtures (comment safety, config constants, dynamic-state-nearby, non-OAuth callbacks, threshold-edge complexity, mid-file magic bytes inside identifiers).
- **Coverage-gap closure: all 30 check IDs from the validation report's §"Test Coverage Gaps" now have explicit pass and fail tests.** Covers CFG-003/011, IOC-001–006, IC-002/003/004/008/011, NB-006–010, NET-001–004, RUN-003/004, ZC-004/006/008/009/012/013.
- **`installation.skillsDirs` aggregation regression test** wires up an OpenClaw-shaped installation with both a shared and a per-agent skills dir and asserts `ctx.skillFiles` contains entries from both.
- **`baselineKey` hostname disambiguation tests** in `src/mcp/tool-baseline.test.ts`: same source on different hostnames produces different keys; `undefined` hostname is treated as a stable default so legacy callers keep the same key.
- Total suite: 1777 passing.

## [0.4.0] - 2026-05-04

### Added

- **Four new coding-agent adapters with 38 security checks** (`GEM-`/`QC-`/`CUR-`/`GHC-`) plus a new Hermes check category (10 `HM-*` checks). Brings VASO to **16 adapters** and **235 total checks** across **16 categories**. Schemas were mapped against real installs over SSH-snapshot scans, so the checks target keys actually written to disk by each tool.

  - **Gemini CLI adapter** (`src/adapters/gemini.ts`): detects `~/.gemini/`, parses JSONC `settings.json`, surfaces OAuth credential files (`oauth_creds.json`, `google_accounts.json`, `mcp-oauth-tokens.json`, `a2a-oauth-tokens.json`); model extraction from `model.name`; binary `gemini`. Project-level `.gemini/settings.json` also picked up under cwd.

  - **Qwen Code adapter** (`src/adapters/qwen-code.ts`): detects `~/.qwen/`, parses JSONC `settings.json`; multi-provider auth (OpenAI / Anthropic / Gemini / Dashscope / Bailian) with model resolved from `model.name` plus `security.auth.selectedType`; falls back to walking `modelProviders[]` for the active provider's id. Binary `qwen`. Project `.qwen/` also detected.

  - **GitHub Copilot CLI adapter** (`src/adapters/copilot-cli.ts`): detects `~/.copilot/`, parses JSONC `config.json` (the `// User settings belong in settings.json.` comment header is stripped before parse) plus `settings.json`, `lsp-config.json`, `command-history-state.json`, and `session-state/`; project `.mcp.json` and `.github/lsp.json` picked up. Model extraction handles both `config.json` and `settings.json` shapes. Binary `copilot`.

  - **Cursor CLI adapter** (`src/adapters/cursor-cli.ts`): detects `~/.cursor/`, parses `cli-config.json` and `mcp.json`; model extraction from `selectedModel.modelId` (active runtime selection) with fallback to `model.modelId`. Supports both `cursor-agent` (npm install) and `agent` (install.sh shim) binary names with `cursor-agent` preferred.

  - **Gemini CLI checks** (`src/checks/gemini-cli/`, 10 checks):
    - **GEM-001** (critical): plaintext API key under `env.*` or `mcpServers.*.env.*` (entropy + known prefixes including OpenRouter, Anthropic, OpenAI, Google `AIza`, GitHub `ghp_`, Slack `xox*`)
    - **GEM-002** (critical): credential file permissions on `settings.json`, `oauth_creds.json`, `google_accounts.json`, `mcp-oauth-tokens.json`, `a2a-oauth-tokens.json`
    - **GEM-003** (critical): overbroad `tools.allowed` shell rules (`run_shell_command`, `run_shell_command(*)`, `run_shell_command(bash|sh|zsh|rm|sudo|curl|...)`); honors `tools.confirmationRequired` precedence
    - **GEM-004** (critical): `security.disableYoloMode: false` — `--yolo` CLI flag remains usable
    - **GEM-005** (warning): `tools.sandbox: false` — tools run unsandboxed
    - **GEM-006** (warning): `tools.sandboxNetworkAccess: true` — sandboxed tools can reach the network
    - **GEM-007** (warning): unpinned MCP server packages (npx/pnpm/yarn/bunx/uvx/pipx without `@version` or `@sha256:`)
    - **GEM-008** (warning): MCP server URL over plaintext `http://` (localhost exempt)
    - **GEM-009** (warning): `general.defaultApprovalMode: "auto_edit"` — file edits run without prompting
    - **GEM-010** (info): plaintext secrets / high-entropy strings in `~/.gemini/memory.md` or `GEMINI.md`

  - **Qwen Code checks** (`src/checks/qwen-code/`, 10 checks):
    - **QC-001** (critical): plaintext API key in `env.*`, `modelProviders[].apiKey`, or `mcpServers.*.env.*`
    - **QC-002** (critical): credential file permissions on `settings.json`, `oauth_creds.json`, `mcp-oauth-tokens.json`, `google_accounts.json`, `.env`
    - **QC-003** (critical): `approvalMode: "yolo"` — auto-approves every tool call
    - **QC-004** (critical): `mcpServers.<name>.trust: true` — MCP server bypasses tool-call approval
    - **QC-005** (warning): broad `permissions.allow` (`Shell(*)`, `Shell`, `*`, `run_shell_command`) with empty `permissions.deny`
    - **QC-006** (warning): unpinned MCP server packages
    - **QC-007** (warning): MCP server URL over plaintext `http://` (localhost exempt)
    - **QC-008** (warning): `approvalMode: "auto-edit"` — file edits auto-approve
    - **QC-009** (info): `telemetry.logPrompts: true` — prompt content uploaded to telemetry endpoint
    - **QC-010** (info): plaintext secrets / high-entropy strings in `~/.qwen/memory.md` or `AGENTS.md`

  - **Cursor CLI checks** (`src/checks/cursor-cli/`, 10 checks):
    - **CUR-001** (critical): `sandbox.mode: "disabled"` — all Cursor tool calls execute on the host with `permissions.allow` as the only gate
    - **CUR-002** (critical): unsafe `approvalMode` (`yolo`, `auto`, `run-everything`, `force`, `auto-everything`)
    - **CUR-003** (critical): overbroad `Shell()` allow rules (`Shell`, `Shell(*)`, `Shell(bash|sh|zsh|fish|cmd|pwsh)`, `Shell(rm|sudo|curl|wget|nc|eval|exec)`); honors `permissions.deny` precedence
    - **CUR-004** (critical): `cli-config.json` / `mcp.json` group/world readable — `authInfo` block contains email, userId, authId in plaintext
    - **CUR-005** (warning): wildcard `permissions.allow` rules (`Shell(*)`, `Write(*)`, `Read(*)`, `WebFetch(*)`, `Mcp(*)`) with empty `permissions.deny`
    - **CUR-006** (warning): MCP server URL over plaintext `http://` in `~/.cursor/mcp.json` (localhost exempt)
    - **CUR-007** (warning): `privacyCache.ghostMode: false` or `privacyMode != 1` — code may be retained for training
    - **CUR-008** (warning): `sandbox.networkAccess: "unrestricted"` (or `"allowed"` / `"all"` / `true`)
    - **CUR-009** (warning): overbroad path/web rules (`Write(*)`, `Read(/)`, `WebFetch(*)`, `Mcp(*)`)
    - **CUR-010** (info): `attribution.attributeCommitsToAgent` or `attributePRsToAgent` — agent authorship recorded in git history

  - **GitHub Copilot CLI checks** (`src/checks/copilot-cli/`, 8 checks):
    - **GHC-001** (critical): `~/.copilot/` directory or files weakened beyond owner-only (covers dir, `session-state/`, `config.json`, `settings.json`, `lsp-config.json`, `command-history-state.json`)
    - **GHC-002** (critical): `allowAllPermissions: true` in `settings.json` — every tool call auto-approves
    - **GHC-003** (critical): plaintext GitHub token in any config (`gho_`, `ghp_`, `ghs_`, `ghu_`, `ghr_`, `github_pat_` prefixes)
    - **GHC-004** (warning): MCP server URL over plaintext `http://` in workspace `.mcp.json` (localhost exempt)
    - **GHC-005** (warning): `updateChannel: "prerelease"` — auto-pulls less-vetted builds
    - **GHC-006** (warning): `experimentalMode: true`
    - **GHC-007** (warning): LSP server `command` containing shell metacharacters (`;&|` `` ` `` `$()<>`) — command-injection vector when the binary is shell-evaluated
    - **GHC-008** (info): plaintext secrets / high-entropy strings in `~/.copilot/instructions/*.instructions.md` and project `.github/copilot-instructions.md`

- **Custom 4-zone graphs** for each of the four new adapters (`Network → MCP/LSP → Approval/Permission → Host FS`), each with one inversion edge labeled "approval bypass" / "permission bypass" gated on the relevant critical check IDs. Graphs validated against the live check registry — registry init fails if any zone graph references an unknown ID.

- **`AgentType`** extended with `'gemini-cli'`, `'qwen-code'`, `'copilot-cli'`, `'cursor-cli'`. **`CODING_AGENTS`** runtime constant grew to 7 entries; checks for the existing 12 `CFG-`/`NET-`/`RUN-`/`POL-` modules continue to skip these new coding agents via `excludedAgents`.

- **Supporting infrastructure** — improvements that benefit existing adapters too:
  - **nvm-aware binary lookup** (`src/adapters/nvm-binary.ts`): walks `~/.nvm/versions/node/*/bin/` and returns the newest match; wired into all 7 coding-agent adapters' `findCLIBinary`. Fixes the SSH non-interactive PATH miss that previously hid nvm-managed installs of `claude`/`codex`/`opencode`/`gemini`/`qwen`.
  - **npm-global `package.json` resolver** (extends `src/adapters/version-query.ts`): `readPackageVersion` now accepts an optional `npmPackageName` and reads `<prefix>/lib/node_modules/<package>/package.json` directly via a single file-read. Snapshot-safe — no directory listing required. Each adapter declares its package name (`@anthropic-ai/claude-code`, `@openai/codex`, `@google/gemini-cli`, `@qwen-code/qwen-code`); a `npmPackageJsonGlobs` helper emits the corresponding probe globs across nvm, `~/.npm-global`, `/usr/local`, `/opt/homebrew`, etc.
  - **Shared JSONC stripper** (`src/core/jsonc.ts`): extracted from `opencode.ts` and reused by Gemini, Qwen, and Copilot adapters whose config files start with `// ...` comment headers.
  - **Probe command allowlist** (`probe/allowlist.go`): added `gemini`, `qwen`, `copilot`, `cursor-agent` so `<bin> --version` is no longer silently rejected. All four `vaso-probe-{linux,darwin}-{amd64,arm64}` binaries rebuilt.
  - **`AgentInstallation.cliBinary`** is now reliably populated for nvm-managed npm installs over SSH snapshots.

- **Lyrie agent adapter + 18 security checks (`LY-001`–`LY-018`).** Lyrie (`~/.lyrie/`) is a Bun turborepo with a Rust Shield (Layer 1), a 10-channel gateway (Telegram / WhatsApp / Discord / Slack / Matrix / Mattermost / IRC / Feishu / Rocket.Chat / WebChat), MCP client+server, diff-view EditEngine with operator approval, and cross-agent migration importers. New check category `lyrie` covers:
  - **LY-001/002** Shield-bypass surface (`LYRIE_SHIELD_MODE=passive`, missing `lyrie-shield` binary)
  - **LY-003** DM pairing policy `open` or unset on any of the 10 channels (Lyrie's documented legacy default — anyone can DM the agent)
  - **LY-004/005** `~/.lyrie/pairing.json` permissions and stale pending pairings
  - **LY-006** Plaintext provider keys / channel tokens with `.env` mode wider than `0600`
  - **LY-007/008/009** Unused provider keys, plaintext Daytona/Modal backend creds, `LYRIE_LOCAL_DRY_RUN=true`
  - **LY-010/011** WebChat reachable on a public host without auth, permissive `LYRIE_WEBCHAT_ORIGINS`
  - **LY-012/013** Stale pending edit approvals and over-permissive `~/.lyrie/edits.json` (TOCTOU diff-swap vector)
  - **LY-014/015** Executable `.ts/.js/.py/.sh` skill files outside Shield scope; group/world-writable skills directory
  - **LY-016/017** Cross-agent migration manifests (informational) and migrations that completed with errors
  - **LY-018** `NODE_ENV=development` while live channel tokens are configured
- Custom 5-zone graph for Lyrie (`Network → Channels → Shield → Engine → Memory`) with two inversion edges: `shield bypass` (LY-001/002) and `DM pairing bypass` (LY-003). Privilege-gradient diagrams now make the Shield Doctrine violation visible.

- **Hermes agent adapter check category + 10 security checks (`HM-001`–`HM-010`).** New check category `hermes` brings VASO to **235 checks across 16 categories**. Anchored on a verified read of the upstream Hermes config space (`~/.hermes/cli-config.yaml`, `~/.hermes/.env`, `~/.hermes/credentials.json`, `~/.hermes/mcp-tokens/*.json`, plus `model.{default,model,provider,api_key,base_url}`, `auxiliary.*`, `delegation.*`, `mcp_servers.<n>.{command,args,env,url}`, `approvals.mode`, `security.{tirith_enabled,tirith_fail_open}` from the upstream `cli-config.yaml.example` and the security/api-server/MCP docs at hermes-agent.nousresearch.com).
  - **HM-001** (critical): plaintext API keys / OAuth tokens / channel bot tokens (Telegram `^\d+:[A-Za-z0-9_-]{35}$`, Discord `^[MN][\w-]{23,28}\.[\w-]{6,7}\.[\w-]{27,38}$`, OpenRouter `sk-or-v1-`, Anthropic `sk-ant-`, GitHub `ghp_`/`gho_`/`github_pat_`, OpenAI `sk-`, Google `AIza`, Slack `xox[baprs]-`, xAI `xai-`) anywhere under the cli-config.yaml tree (incl. `mcp_servers.<n>.env.*`); skips `${ENV_VAR}` references; entropy + name heuristic for unrecognised forms
  - **HM-002** (critical): `~/.hermes/.env` mode wider than `0600` when it contains `*_API_KEY` / `*_TOKEN` / `*_SECRET` / `*_KEY` / `BEARER` / `PASSWORD`
  - **HM-003** (critical): `~/.hermes/credentials.json`, `~/.hermes/auth.json`, and every `~/.hermes/mcp-tokens/*.json` mode wider than `0600`
  - **HM-004** (critical): `API_SERVER_HOST` non-loopback **and** `API_SERVER_KEY` empty/unset — Hermes API server (default `:8642`) accepts unauthenticated requests with full access to the agent toolset including terminal commands
  - **HM-005** (warning): `API_SERVER_HOST` non-loopback **and** `API_SERVER_CORS_ORIGINS` empty or `*` — any browser tab on any origin can drive the Hermes API
  - **HM-006** (critical): non-loopback `http://` URL in any `model.base_url` / `auxiliary.*.base_url` / `delegation.base_url` / `mcp_servers.<n>.{url,http_url,sse_url}` — prompts, tool calls, and bearer tokens traverse unencrypted
  - **HM-007** (warning): inference / MCP endpoint hostname outside the known-provider allowlist (openrouter, anthropic, openai, googleapis, NVIDIA, ollama, lmstudio, groq, mistral, cohere, perplexity, deepseek, x.ai, AWS Bedrock, HuggingFace, NousResearch, chatgpt) — possible exfiltration endpoint harvesting prompts + bearer tokens
  - **HM-008** (critical): `approvals.mode: off` in cli-config.yaml **or** `HERMES_YOLO_MODE` truthy in .env — tool calls (incl. terminal commands) execute without operator confirmation
  - **HM-009** (warning): `security.tirith_enabled: false` **or** (`security.tirith_fail_open: true` (default) and `tirith` binary missing from PATH) — pre-exec dangerous-command scanning silently disabled
  - **HM-010** (warning): MCP server in `mcp_servers.<n>` invoked via shell-c (`bash -c …` / `sh -c …`), running an unpinned package via `npx`/`pnpm`/`yarn`/`bunx`/`uvx`/`pipx`, or pointing to a world-writable command path — supply-chain and TOCTOU vectors

- **Custom 5-zone graph for Hermes** (`Network → API Server → Approvals + Tirith → Tool Fan-out → Remote Endpoints`) with three inversion edges: `unauth API bypass` (HM-004), `approval bypass` (HM-008), and `plaintext / exfil endpoint` (HM-006/HM-007). Hermes was previously using the generic 4-zone fallback; the custom graph now reflects its multi-stage gateway → approval → tool surface architecture.

- **`CheckCategory`** type extended with `'hermes'`. Visualization category-label map updated (`Hermes`).

- **Model detection for the six remaining framework adapters.** `vaso detect` now reports the configured LLM model for Hermes, IronClaw, Lyrie, NanoClaw (where applicable), PicoClaw, and ZeroClaw. Schemas were verified against each upstream repo rather than inferred from existing scanner code:
  - **Hermes** (`~/.hermes/cli-config.yaml`, with legacy `config.yaml` fallback): reads `model.default` (or the `model.model` alias the CLI also accepts), with `model.provider` and `model.base_url` treated as sibling metadata for the active model — not separate model slots. `.env` overrides via `HERMES_MODEL` / `HERMES_DEFAULT_MODEL` / `OPENROUTER_MODEL` paired with `HERMES_PROVIDER`.
  - **IronClaw**: env-var-driven (no `[model]` table in `config.toml`). `LLM_BACKEND` selects backend ∈ {`nearai`, `ollama`, `openai_compatible`, `openai`, `anthropic`, `github_copilot`, `tinfoil`, `openai_codex`, `gemini_oauth`, `minimax`} and the paired `<NAME>_MODEL` env var holds the id. When `LLM_BACKEND` is unset, surfaces every populated `*_MODEL` with `via='env-detected'` so the user sees what's actually configured.
  - **Lyrie** (`~/.lyrie/.env`): `LYRIE_MODEL` / `LYRIE_DEFAULT_MODEL` / `LYRIE_FALLBACK_MODEL`, plus per-channel `LYRIE_<CHANNEL>_MODEL` (telegram, discord, slack, …) surfaced with `via=<channel>`.
  - **NanoClaw**: returns `[]` by design — NanoClaw delegates to an inner CLI (`claude`, `codex`, `opencode`) selected via `Session.agent_provider` stored in SQLite, so the model question is answered by the inner agent's adapter.
  - **PicoClaw** (`~/.picoclaw/config.json`): reads `agents.defaults.model_name` against the top-level `model_list[]` array. Each entry's `model: "<provider>/<id>"` is split; load-balance pool entries (duplicate `model_name` with different `api_key`/`api_base`) dedupe to a single ModelRef.
  - **ZeroClaw** (`~/.zeroclaw/config.toml`): reads top-level `default_provider` + `default_model`; strips embedded base-URL from provider strings (e.g. `"anthropic-custom:https://api.z.ai/..."` → `"anthropic-custom"`); surfaces `model_routes[]` entries with route name as `via`, plus `[reliability.model_fallbacks]` entries as `via=fallback:<slot>`.

- **Gemini CLI active-model detection from session transcripts.** `/model set <name>` without `--persist` only mutates the in-memory session — `~/.gemini/settings.json` typically contains only auth info. Resolution now matches the CLI itself (`packages/cli/src/config/config.ts:853`): `GEMINI_MODEL` env > `settings.model.name` > tail of the latest `~/.gemini/tmp/<project-id>/chats/session-*.jsonl`. The session walker picks the lex-greatest filename across all projects (timestamp prefix sorts chronologically) and reads the last `"model":"..."` record — same pattern as the existing Codex session walker. Probe manifest extended with `~/.gemini/tmp/*/chats/session-*.jsonl` and a `~/.gemini/tmp` directory listing so SSH scans collect the data. Default fallback `auto-gemini-3` is intentionally NOT surfaced — it indicates the user hasn't configured anything, not a real selection.

- **`-o, --output <file>` for `vaso detect`.** Mirrors `vaso scan`'s file-write contract. Works for local detection, snapshot-based detection (`--snapshot`), and SSH multi-host detection (`--host`/`--inventory`) — JSON aggregates to a single per-host array; terminal text concatenates per-host renders with a divider. Prints the same `Report written to <path>` confirmation as `scan`.

- **Top-level `version` field on `AgentScanResult`** (`src/core/types.ts:102`). Populated from `installation.version` in `engine.scanAgent`. Lets JSON consumers read `agents[i].version` directly without drilling into `agents[i].installation.version` — matches the flat shape `vaso detect` already emits.

- **Default `label` on `SSHTarget`.** `parseSSHTarget` and `parseInventory` now default `target.label` to `user@host` (or `user@host:port` when port ≠ 22) when no label is supplied. Previously a bare `--host conde@example.com` left `target.label` undefined, forcing every consumer to fall back to formatting the user/host themselves. Explicit YAML `label:` entries still take precedence.

### Fixed

- **`vaso scan -o` over SSH.** The `-o, --output` flag was being ignored when scanning remote hosts via `--host`/`--inventory`; results were always emitted to stdout instead of the requested file. Now writes a single aggregated file per scan: JSON gets a structured per-host array (`{target, durationMs, error, result}`); other formats get per-host renders concatenated with a plain divider for readability without ANSI escapes.

- **Snapshot directory listings: trailing slashes leaking into consumers.** The Go probe (`probe/collector.go:217`) appends `/` to directory entry names so a flat list can distinguish dirs from files. That trailing slash leaked through `SnapshotFSProvider.readdir` into callers that `path.join()` the name back together, producing `//` and breaking subsequent prefix lookups. Concrete failure: gemini-cli's session-jsonl walker called `fs.readdirEntries('~/.gemini/tmp')` and got back names like `'conde/'`; `join(parent, 'conde/')` yielded `'~/.gemini/tmp/conde/'`, and `hasChildPaths` then searched with prefix `'~/.gemini/tmp/conde//'` which matched no real file path — every project subdir was marked `isDirectory=false` and the walker bailed before reaching any session file. Codex's session walker had the same latent bug (filters `/^\d+$/` would fail against `'2026/'`). Fix: strip trailing `/` in `readdir()` so all callers — including the prefix-derivation fallback — see clean basenames. Codex's session walker is now usable over SSH the moment any session JSONL exists.

- **Probe manifest now collects MCP host configs.** The CLI-emitted manifest (`vaso probe manifest`, consumed by `vaso-probe`) was missing the cross-host MCP config files that `vaso mcp scan` reads, so snapshot-based scans under-reported MCP findings. Added:
  - `~/.claude/mcp.json` (Claude Code adapter manifest)
  - `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS)
  - `~/.config/Claude/claude_desktop_config.json` (linux)
  - `~/.cursor/mcp.json`
  - `~/.codeium/windsurf/mcp_config.json`
- **`vaso-probe` `DefaultManifest()` fallback corrected and extended.** Used when the probe is invoked without `-manifest`. Fixed wrong Claude Desktop linux path (`~/.config/claude-desktop/...` → `~/.config/Claude/...`, case-sensitive), added Claude Code, Codex, and Windsurf paths, and added `CLAUDE_`/`ANTHROPIC_`/`CODEX_`/`OPENAI_` env prefixes. Comment now states the fallback is minimum-viable and operators should prefer the CLI-emitted manifest.

## [0.3.0] - 2026-04-27

### Added

#### Visualization Config Emission (PRD-006)

`vaso visualize` emits USecVisLib config files (TOML/JSON/YAML) for three diagram types. VASO does not bundle, sidecar, or call a USecVisLib server — users render externally with `usecvis` (CLI, REST, or MCP).

- **`vaso visualize`** command (`src/commands/visualize.ts`):
  - Two modes: fresh scan (default) or replay from `-i scan.json`
  - Flags: `-o <dir>` (default `./vaso-visualizations/`), `--vis-format toml|json|yaml` (default `toml`), `--diagrams attack-tree,privilege-gradient,component`, `-a <agent>`, `--all-users`
  - Writes one file per (installation × diagram) plus a `README.md` with the corresponding `usecvis` command for each file

- **`ZoneGraph` model** (`src/core/types.ts`): per-adapter privilege-gradient declaration with zones, components, edges, and explicit inversion paths gated on check-failure triggers
  - Validator (`src/core/zone-graph-validator.ts`) runs after registry init; fails CI if any graph references an unknown check ID
  - Generic 4-zone fallback (`src/core/default-zone-graph.ts`) used by adapters that don't declare a custom graph
  - Custom graphs for the five adapters with materially distinct surfaces:
    - **NemoClaw** — 5 zones with explicit GPU isolation boundary
    - **IronClaw** — gRPC gateway zone instead of generic HTTP
    - **Nanobot** — chat-platform edge zone (Discord/Slack)
    - **Claude Code** — MCP transport + tool-execution zones with hooks side-channel component
    - **Codex** — sandbox-mode zone (read/workspace/danger)
  - Generic fallback used by OpenClaw, NanoClaw, PicoClaw, ZeroClaw, Hermes
  - Each custom graph declares one inversion edge mapping a real attack class (sandbox bypass, permission bypass, channel-driven exec)

- **Visualization data models** (`src/visualizations/models/`):
  - `attack-tree-model.ts` — pure `ScanResult → AttackTreeModel` shaper; root → category → finding tree, skips passed checks, attaches CVSS to leaves
  - `topology-model.ts` — pure `ScanResult → TopologyModel` shaper; host → agents → gateways
  - `cvss-mapper.ts` — real CVSS extracted from advisory check evidence when present (`cvss=N.N` or `CVSS: N.N` patterns); severity-mapped fallback (`critical→9.0, warning→5.0, info→2.0`) for findings without CVSS data. The bundle README documents the mapping explicitly.

- **USecVisLib config serializers** (`src/visualizations/serializers/`):
  - `usecvis-shape.ts` — three transformers matching USecVisLib's exact schemas: `[tree]/[nodes]/[edges]` for attack trees, `[[zones]]/[[components]]/[[influence_types]]/[[influences]]` for privilege gradient, `layers/connections` for component diagrams
  - `format.ts` — `serialize(shape, 'toml'|'json'|'yaml')` via `smol-toml` / `JSON.stringify` / `yaml`

- **`AgentAdapter.getZoneGraph?()`** added as an optional method on the adapter interface.

#### Test Suite

- 1173 unit tests across visualizations module (78 new across Phases 1–4)
- `src/adapters/zone-graphs.test.ts` exercises every registered adapter's graph against the real check registry

## [0.2.1] - 2026-04-27

### Added

#### Framework-Specific Check Categories

- **OpenClaw checks** (`src/checks/openclaw/`, 6 checks):
  - **OC-001**: sub-agent config security downgrade — flags when `agents/<name>/agent.{yaml,json}` overrides global hardening (TLS off, sandbox off, gateway re-bound publicly, auth weakened) via the adapter's silent `deepMerge`
  - **OC-003**: legacy `.clawdbot` / `.moltbot` directories still loaded by the adapter alongside `.openclaw`
  - **OC-004**: `OPENCLAW_HOME` env var redirecting config loading outside the user home (escalates to critical when redirected to world-writable locations like `/tmp`, `/dev/shm`)
  - **OC-005**: `.openclaw-${profile}` config relaxes the security posture relative to the default `.openclaw` config
  - **OC-006**: `memory.json` and `conversations.db` permissions (should be 0600; conversation history with PII / embedded secrets) — fixable
  - **OC-007**: `/etc/openclaw` directory or system configs writable by non-root — critical hijack vector
  - Shared `posture.ts` helper extracts security posture (TLS, auth mode, gateway host/port, sandbox, approval) and detects downgrades; used by OC-001 and OC-005

- **NanoClaw checks** (`src/checks/nanoclaw/`, 5 checks):
  - **NC-001**: overbroad `mount-allowlist.json` entries (root globs `/`, `/*`; system dirs `/etc`, `/root`, `/var/log`, `/proc`, `/sys`; credentials dirs `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.config`, `~/.kube`, `~/.docker`)
  - **NC-002**: `mount-allowlist.json` group/world-writable — any local user can grant the agent additional filesystem scope; fixable
  - **NC-003**: `NANOCLAW_HOME` redirected to non-home / world-writable runtime directory (warning, escalates to critical for `/tmp`-class paths)
  - **NC-004**: `NANOCLAW_HOST=0.0.0.0` or unspecified while `NANOCLAW_PORT` is set — public listener exposure; fixable
  - **NC-005**: skills directory group/world-writable — persistent skill-injection vector

- **CheckCategory** type extended with `'openclaw'` and `'nanoclaw'`

#### PicoClaw Coverage Strategy
- PicoClaw deliberately ships **no `picoclaw/` check category** — its thin surface (`config.json` + `auth.json` + `skills/`) is fully covered by generic CFG-001/002/003/004, SKL-*, ADV-*, IOC-* checks. Documented rationale in `CLAUDE.md` so the decision is durable.

### Changed

#### `defineCheck` Migration Completed
All 146 check modules previously authored against the raw `CheckModule` interface now use the `defineCheck` helper from `src/core/check-builder.ts`, completing the migration started in v0.2.0:
- **IOC** (8): `bd64617`
- **IronClaw** (12): `4b0bd2d`
- **Nanobot** (12): `652e21e`
- **ZeroClaw** (14): `0503d14`
- **MCP** (18 remaining): `d058172`
- **config** (24): `f262068`
- **skills** (11 remaining): `cfbd23e`

Net effect: −760 lines across 99 check files. Pure refactor — no behavior change.

### Test Suite
- 1095 unit tests across 79 files (was 1044/78 at v0.2.0)
- 27 new tests for OpenClaw checks, 24 new tests for NanoClaw checks

## [0.2.0] - 2026-04-27

### Added

#### Network Scanning — FSProvider Abstraction (Phase A)
- **`FSProvider` interface** (`src/core/fs-provider.ts`): abstracts all filesystem and process I/O behind a swappable interface (`readFile`, `readdir`, `readdirEntries`, `access`, `stat`, `realpath`, `exec`, `execSync`, `platform`, `homedir`) — the prerequisite for remote and snapshot-based scanning
- **`LocalFSProvider`** (`src/core/local-fs-provider.ts`): wraps `node:fs/promises` and `node:child_process` with zero behavior change — existing local scans work identically
- **`ScanContext.fs`**: all 117 check modules now receive `FSProvider` via `ctx.fs` instead of importing `node:fs` directly; all 7 adapters receive it via `DetectOptions.fs`
- **Mechanical migration**: 85 files changed — all direct `node:fs/promises`, `node:fs`, `node:child_process`, and `node:os` imports removed from checks and adapters; core utilities (`config-loader`, `utils`, `rules/loader`, `mcp/discovery`, `mcp/source-resolver`) accept optional `FSProvider` parameter
- **`ScanEngine`** constructor accepts optional `FSProvider`, defaults to `LocalFSProvider`; injects into all `ScanContext` objects
- Zero logic changes to any check module — only the I/O source is now swappable
- All 793 tests pass identically after migration

#### Network Scanning — Snapshot Scanning & vaso-probe (Phase B)
- **`SnapshotFSProvider`** (`src/core/snapshot-fs-provider.ts`): serves `readFile`, `readdir`, `access`, `stat`, `exec`, and `execSync` from an in-memory `ProbeSnapshot` JSON object; throws descriptive errors when requested data was not collected in the snapshot
- **`ProbeSnapshot` / `ProbeManifest` types** (`src/core/snapshot-types.ts`): define the collection contract between scanner and probe — files, directories, commands, env vars, privilege metadata
- **`getProbeManifest()`** implemented on all 7 adapters: each declares the files, directories, globs, commands, and env prefixes it needs collected from a remote host
- **`buildProbeManifest()`** (`src/core/manifest-builder.ts`): merges adapter manifests with runtime/network check commands (netstat, ss, ps, crontab, launchctl), deduplicates
- **`vaso scan --snapshot <path>`**: loads a pre-collected JSON snapshot, creates `SnapshotFSProvider`, runs the full scan pipeline — checks see no difference between local and snapshot scanning
- **`vaso probe manifest`**: generates the full collection manifest (JSON) for all registered adapters
- **`vaso probe validate <path>`**: validates a snapshot file structure and prints summary (host, platform, file/dir/command counts, privilege level)
- **`ScanResult.host`**: populated from `snapshot.hostname` when scanning a snapshot; reporters show host in output
- **Privilege warnings**: scanner shows a warning when the snapshot was collected as a non-root user, indicating limited scan coverage
- **`vaso-probe` Go binary** (`probe/`): zero-dependency static binary for Linux and macOS (amd64/arm64) that collects files, directories, commands, and env vars according to a manifest
  - Privilege-aware: as root, enumerates all user home directories; as regular user, scans current user only
  - `--escalate` flag: attempts passwordless sudo re-execution for full-coverage scanning
  - Hardcoded command allowlist prevents arbitrary command execution
  - `--manifest` flag for custom collection; built-in default manifest covers all 7 agent frameworks
  - Cross-compilation via `Makefile` with `CGO_ENABLED=0` for 4 targets
  - Uses `doublestar` library for glob expansion
- 29 new tests for `SnapshotFSProvider` covering all methods, error cases, and edge cases
- Total tests: 822

#### Network Scanning — SSH Remote Transport (Phase C)
- **`vaso scan --host user@host`**: scan a remote host over SSH in a single command — automatically pushes the probe binary, executes it, and streams the snapshot back
- **`vaso scan --host user@host1 --host user@host2`**: parallel multi-host scanning with configurable concurrency
- **`vaso scan --inventory hosts.yaml`**: scan hosts listed in a YAML inventory file with per-host user, port, identity, sudo, and label overrides
- **SSH ControlMaster multiplexing**: authenticates once (supporting interactive password prompts), then reuses the connection for all subsequent ssh/scp commands — no repeated password prompts
- **Automatic platform detection**: detects remote OS and architecture via `uname`, selects the correct cross-compiled probe binary (linux/darwin, amd64/arm64)
- **`--ssh-key <path>`**: specify SSH identity file for remote connections
- **`--ssh-timeout <seconds>`**: configurable SSH connection timeout (default 60s)
- **`--sudo`**: pass `--escalate` to the remote probe for privilege escalation via passwordless sudo
- **Per-host error isolation**: failed hosts produce error entries without blocking other hosts
- **`ScanResult.label`**: optional label for host identification in reports
- **SSH transport layer** (`src/transport/`): `ssh.ts` (target parser, ControlMaster, remote probe execution), `inventory.ts` (YAML inventory parser), `multi-host.ts` (parallel scanning orchestrator)
- No SSH library dependency — uses the system `ssh`/`scp` binaries, respects `~/.ssh/config` for host aliases and jump hosts
- 22 new tests for SSH target parsing, inventory parsing, and multi-host aggregation
- Total tests: 843

#### Hermes Agent Support
- **Hermes adapter** (`src/adapters/hermes.ts`): detects Hermes Agent (Nous Research) installations by scanning `~/.hermes` (or `HERMES_HOME` env override) for `config.yaml` and `.env` config files
- **Gateway detection**: extracts API server binding from `platforms.api_server` config (default `127.0.0.1:8642`)
- **Skills directory**: reports `~/.hermes/skills/` for skill code analysis
- **CLI version extraction**: queries `hermes version` / `hermes --version` for installed version
- **Probe manifest**: declares file paths, glob patterns, commands, and env prefixes (`HERMES_`) for remote snapshot scanning
- **Credential and memory path discovery**: `.env`, `credentials.json`, `memory/`, `conversations.db`
- **Go probe updated**: `hermes` added to command allowlist; `DefaultManifest()` includes `~/.hermes` config files, skills/optional-skills globs, `hermes version` command, directory listings, and `HERMES_` env prefix
- `'hermes'` added to `AgentType` union; adapter registered in CLI alongside existing 7 adapters
- 16 new unit tests covering detection, config loading, gateway extraction, env override, probe manifest
- Total tests: 859

#### Cross-Platform Installer Script
- **`install.sh`** — one-liner bash installer for Linux, macOS, and WSL: `curl -fsSL https://raw.githubusercontent.com/vulnex/vaso/main/install.sh | bash`
- Detects platform (macOS, Linux, WSL via `/proc/version` check) and architecture
- Validates Node.js 18+ and npm are present; if missing, prints platform-specific install instructions (Homebrew for macOS, apt/dnf for Linux/WSL, nvm for all, direct download link)
- Auto-detects whether `sudo` is needed for global npm install by checking npm prefix writability
- Post-install verification: confirms `vaso` is in PATH, prints version and getting-started commands; if npm global bin isn't in PATH, shows the exact `export PATH` line to add

#### Hybrid E2E Test Suite — Agent Fixtures + Real MCP Servers
- **34 local end-to-end tests** across 5 test files in `testing/e2e/` — exercises the full CLI as a child process against realistic agent installations, no Docker required
- **Fixture installation engine** (`testing/e2e/helpers/setup.ts`): creates temporary HOME directories with agent fixtures copied from `testing/fixtures/`, rewriting NanoClaw `NANOCLAW_HOME` paths and setting file permissions to simulate insecure/secure scenarios; supports all 6 agents (OpenClaw, NanoClaw, PicoClaw, IronClaw, Nanobot, ZeroClaw)
- **CLI runner** (`testing/e2e/helpers/cli-runner.ts`): spawns `node dist/cli.js` as a child process with custom `HOME` env; exports `runVasoCLI()` (raw output), `runVasoJSON()` (parsed `ScanResult`), and `runVasoJSONArray()` (for `vaso detect --format json`); brace-matching JSON extraction reused from integration helpers
- **MCP config generator** (`testing/e2e/helpers/mcp-config.ts`): resolves real installed MCP server package entry points via `createRequire()`, generates `claude_desktop_config.json` with optional insecure entries and vulnerable server source paths
- **`detect.e2e.test.ts`** (4 tests): all 6 agents discovered, `--agent` filtering, terminal output validation, installDir path verification
- **`scan.e2e.test.ts`** (15 tests): full scan across all 6 agents, cross-agent checks (CFG-001, CFG-008), agent-specific checks (IC-005, ZC-001), agent filter, secure vs insecure score comparison
- **`mcp-scan.e2e.test.ts`** (8 tests): MCP scan with insecure entries (MCP-002, MCP-003), vulnerable server source analysis (MCP-004, MCP-005, MCP-006), clean packages score comparison
- **`mcp-list.e2e.test.ts`** (2 tests): terminal and JSON MCP server listing with 4 real packages
- **`output-formats.e2e.test.ts`** (5 tests): JSON, SARIF, markdown, HTML, and terminal format validation
- **Global setup/teardown**: ensures `dist/cli.js` is built before tests; cleans leftover `vaso-e2e-*` temp dirs after
- **Parallel-safe**: each test creates its own temp HOME passed via env to child processes — no global state mutation
- **4 MCP server devDependencies**: `@modelcontextprotocol/server-filesystem`, `server-memory`, `server-everything`, `server-sequential-thinking`
- **`glob` devDependency** for recursive file permission setting in fixture setup
- **npm scripts**: `test:e2e` runs E2E suite; `test:all` updated to `vitest run && npm run test:e2e && npm run test:integration` (speed order: unit → e2e → Docker)
- Separate vitest config (`testing/vitest.config.e2e.ts`) with 60s test timeout, 120s hook timeout
- Test suite now at 474 unit tests + 34 e2e tests across 45 test files

#### Example User Plugins
- **4 example plugins** in `examples/plugins/` demonstrating the full `VasoPluginAPI` surface — copy to `~/.vaso/plugins/` to use
- **`env-hygiene-check.mjs`** (simple): `api.registerCheck()` — registers USR-001 (warning) that detects development/debug environment patterns in agent configs (NODE_ENV=development, DEBUG=true, localhost references, private IPs); scans both parsed config data (structured walk) and raw text (line-by-line)
- **`csv-reporter.mjs`** (simple): `api.registerReporter()` — registers `csv` output format for `vaso scan --format csv`; RFC 4180-compliant with header row, one row per evidence item (denormalized), summary row with score/grade, proper field escaping
- **`compliance-audit-checks.mjs`** (medium): `api.registerChecks()` — batch-registers 3 compliance checks (USR-010 audit logging/critical, USR-011 log rotation/warning, USR-012 data retention/warning); USR-010 includes `fix()` method returning remediation guidance; shared `findInConfigs()` helper avoids duplication
- **`custom-agent-adapter.mjs`** (advanced): all three APIs in one plugin — registers a ToolForge agent adapter (`api.registerAdapter()`), an agent-scoped sandbox check USR-020 (`supportedAgents: ['toolforge']`), and a `summary-line` CI/CD reporter (`VASO: 85/100 (B) | 0 critical, 2 warning, 1 info | openclaw`)
- **`examples/plugins/README.md`**: installation instructions, API overview, `USR-` check ID convention

#### MCP OAuth 2.1 Security Checks (MCP-011 through MCP-018)
- **MCP-011** (OAuth Endpoint HTTPS): detects HTTP authorization/token endpoint URLs in config env blocks and source code; exempts localhost/127.0.0.1/[::1] for local development (critical)
- **MCP-012** (OAuth Client Secret Exposure): detects plaintext `client_secret`, `access_token`, `refresh_token` in env blocks via key name patterns, value patterns (Google OAuth, JWT, Ory tokens), and Shannon entropy analysis (>4.5 bits); masks values in evidence (critical)
- **MCP-013** (Missing PKCE): detects OAuth authorization flows without `code_challenge`/`code_verifier` parameters and flags `code_challenge_method: "plain"` (must be S256); uses ±15 line radius for context-aware detection (critical)
- **MCP-014** (Insecure Token Storage): detects tokens in `console.log`, `localStorage`/`sessionStorage`, `writeFile`, URL query parameters, and string concatenation into URLs (critical)
- **MCP-015** (Token Passthrough): detects MCP servers forwarding received authorization headers or context tokens to downstream API calls — confused deputy risk (critical)
- **MCP-016** (Insecure Redirect URI): detects HTTP redirect/callback URIs in config and source, wildcard redirect patterns, and user-controlled redirect targets via `req.query`/`req.params` (warning)
- **MCP-017** (Overly Broad OAuth Scopes): detects wildcard (`*`), `admin`, `root`, `full_access` scopes in config and source; flags excessive scope counts (>10 individual scopes) (warning)
- **MCP-018** (Missing State Parameter): detects OAuth authorization URL construction without `state` parameter, hardcoded/static state values, and callback handlers that don't verify state; distinguishes config constants from active URL construction (warning)
- `OAUTH_SECRET_PATTERNS` and `OAUTH_TOKEN_VALUE_PATTERNS` added to `src/core/patterns.ts` for reuse across OAuth checks
- Test fixtures: `vulnerable-oauth-server/index.js` (exhibits all 8 anti-patterns), `safe-oauth-server/index.js` (PKCE S256, dynamic state, encrypted storage, service credentials for downstream)
- 19 new tests covering all 8 checks (fail/pass cases + edge cases for localhost exception, plain PKCE, small scope sets)
- Test suite now at 474 tests across 40 test files
- Total MCP checks: 18 (MCP-001 through MCP-018)

#### User Plugin System — `vaso ext`
- **User plugin loader** (`src/user-plugins/loader.ts`): discovers and loads `.js`/`.mjs` plugins from `~/.vaso/plugins/` drop folder — supports single-file plugins, directory plugins (resolved via `package.json` main → `index.mjs` → `index.js`), and async `register()` functions
- **Plugin API** (`src/user-plugins/types.ts`): `VasoPlugin` interface (what plugins export), `VasoPluginAPI` (registration hooks for checks, adapters, and reporters), `LoadedPlugin` (internal tracking with path, name, status, error, and registered item lists)
- **Two-layer error isolation**: outer try/catch around import+register, inner try/catch around each individual registration call — broken plugins log warnings but never crash VASO
- **`vaso ext list`** command: lists all loaded user plugins with status, registered counts, paths; supports `--format json`
- **`vaso ext info <name>`** command: shows detail for one plugin including registered checks, adapters, reporters; supports `--format json`
- **CLI integration**: user plugins load in `preAction` hook after banner, before IOC database init; plugins load after built-in checks so duplicate IDs are caught (built-ins win)
- Uses `pathToFileURL()` for cross-platform dynamic import, `mod.default ?? mod` for ESM/CJS compatibility — zero new dependencies
- Hidden files (`.` or `_` prefix) and non-JS files are skipped automatically
- 15 new tests in `src/user-plugins/loader.test.ts`: empty/nonexistent dirs, valid plugin loading with meta tracking, syntax errors, missing register(), duplicate check IDs (partial load), directory resolution (package.json/index.mjs/index.js), hidden file skipping, async register, thrown errors, getLoadedPlugins caching
- Test suite now at 470 tests across 41 test files

#### Skill Audit Command — `vaso skill audit <path>`
- **`vaso skill audit <path>`** command: pre-install single-skill security scanning — point at a local skill directory and get a security report before installing it into an agent framework
- **`scanSkill()` method** on `ScanEngine` (modeled on `scanMCP()`): creates a synthetic `ScanContext` with `agent: 'skill-audit'`, runs only `skills` + `ioc` category checks against the skill directory
- **`src/commands/skill-audit.ts`**: validates path exists and is a directory, discovers code files via `getSkillFiles()`, early-returns with message if no code files found, sets `exitCode=1` on critical findings
- **`skill` command group** in CLI with `audit` subcommand: `vaso skill audit <path> [-f format] [-o file] [--no-color]` — leaves room for future `vaso skill list`, etc.
- `'skill-audit'` added to `AgentType` union so reporters display the correct agent type
- 7 new tests in `src/commands/skill-audit.test.ts`: missing path, not a directory, no code files, happy path, critical findings, `--output` file write, engine error handling

#### Interactive TUI Fix Mode
- **Per-fix interactive confirmation** for `vaso fix`: when neither `--yes` nor `--dry-run` is set, prompts for each fixable finding with `[y]es / [n]o / [a]ll / [q]uit`
- **`src/remediation/prompt.ts`**: standalone prompt module using `node:readline` (zero new dependencies) — displays check ID, color-coded severity, message, evidence, and fix description; empty/unrecognized input defaults to `'no'` (safe default)
- **Non-TTY safety**: `RemediationEngine.fix()` detects non-interactive terminals and requires explicit `--yes` in CI/script environments
- **`'all'` response**: sets `applyAll=true`, applying the current and all remaining fixes without further prompts
- **`'quit'` response**: skips current fix and returns accumulated results immediately
- Backward compatible: `--yes` and `--dry-run` behavior is identical to previous implementation
- 13 new tests in `src/remediation/prompt.test.ts`: all input variants (y/yes/n/no/a/all/q/quit/empty/unrecognized), readline close, display output, minimal finding
- 9 new tests in `src/remediation/engine.test.ts`: `--yes` no prompts, `--dry-run` no prompts, interactive yes/no/quit/all, fix failure in interactive mode, non-TTY warning, non-TTY with `--yes`
- Test suite now at 440 tests across 39 test files

#### Plugin Mode — `before_agent_start` Security Gate
- **Plugin system** (`src/plugins/`): dual-mode architecture allowing VASO to run as an agent plugin that hooks into each framework's startup lifecycle, blocking agents when critical security issues are found
- **Plugin types** (`src/plugins/types.ts`): `PluginConfig`, `PluginManifest`, `PluginInfo`, `PreStartScanResult` interfaces; `PLUGIN_AGENTS` constant and `DEFAULT_PLUGIN_CONFIG` defaults (blockOnCritical: true, blockOnWarning: false, timeout: 30s)
- **Plugin runner** (`src/plugins/runner.ts`): programmatic `runPreStartScan(agent, config?)` for in-process scanning with `Promise.race` timeout; `evaluateScanResult()` pure function for block policy evaluation; errors and timeouts always allow startup (safe default — VASO errors must never prevent a legitimate agent from starting)
- **Plugin installer** (`src/plugins/installer.ts`): `installPlugin()` generates framework-specific `.mjs` files using `execFileSync` subprocess to run `vaso scan --agent <type> --format json`; `uninstallPlugin()` with idempotent ENOENT handling; `getPluginStatus()` reads manifest sidecars; `loadPluginConfig()`/`savePluginConfig()` for `~/.vaso/plugin-config.json`; `resolveVasoBinaryPath()` tries `process.argv[1]`, `which vaso`, fallback to `'vaso'`
- **Framework-specific plugin exports**:
  - **OpenClaw**: `export default { name, version, hooks: { before_agent_start } }` → `~/.openclaw/plugins/vaso-security.mjs`
  - **NanoClaw**: `export const lifecycle = { onBeforeStart }` → `~/.config/nanoclaw/plugins/vaso-security.mjs`
  - **PicoClaw**: `export default { name, version, handlers: { preStart } }` → `~/.picoclaw/plugins/vaso-security.mjs`
- **CLI commands** (`src/commands/plugin.ts`): `vaso plugin install -a <type> [--force]`, `vaso plugin uninstall -a <type>`, `vaso plugin status [-a <type>] [-f <format>]`
- 37 new tests in `src/plugins/plugin.test.ts`: `evaluateScanResult` (9 cases — no findings, block on critical, no block when disabled, block on warning, excludeChecks filtering, summary counts, findings arrays, elapsed/score/grade, priority), `generatePluginContent` (7 — OpenClaw/NanoClaw/PicoClaw export shapes, binary path embedding, version embedding, ESM syntax, execFileSync usage), `getPluginInstallPath` (3 — correct path per agent), `loadPluginConfig` (1 — defaults on missing file), CLI commands (9 — invalid agent rejection, install success, force passthrough, conflict suggestion, uninstall confirmation, status terminal/JSON rendering, agent filter), `runPreStartScan` (6 — blocked on critical, safe on error, safe on timeout, idempotent init, agent filter, custom config)
- Test suite now at 411 tests across 36 test files

#### IOC Auto-Updater with Ed25519-Signed Threat Feeds
- **Pull-based feed system** (`src/ioc/updater.ts`): fetches remote IOC feed JSON + detached `.sig` from configurable URL, verifies Ed25519 signature via `node:crypto`, persists to `~/.vaso/ioc/`, merges additively with bundled data — zero new npm dependencies
- **Ed25519 signature verification**: mandatory on every fetch and every cache load (catches local tampering); 64-byte signature length enforcement; key pinning with no TOFU — rotation requires new VASO release
- **Feed version monotonicity**: rejects downgrades (remote version must exceed cached version); `--force` flag overrides staleness and version checks
- **Additive merge**: remote feed extends bundled data (union with deduplication for strings via Set, RegExp by source+flags, BinaryPattern by name+type); bundled indicators are always present regardless of feed state
- **Staleness detection**: configurable threshold (default 7 days) based on `~/.vaso/ioc/metadata.json` timestamps; stale/missing feed triggers yellow warning on all non-update commands
- **`initIOCDatabase()`**: async startup initializer loads cached feed and merges with bundled data; idempotent; `getIOCDatabase()` falls back to bundled-only if never called
- **`vaso update` command**: real fetch-verify-persist-reload flow replacing the previous stub; prints per-field new indicator counts and merged database totals; accepts `--url <url>` (custom feed) and `--force` options
- **CLI preAction hook**: now async; calls `initIOCDatabase()` on every command; shows staleness warning for non-update commands
- **Feed type definitions** (`src/ioc/feed-types.ts`): `IOCFeed`, `IOCFeedData`, `SerializedRegExp`, `SerializedBinaryPattern`, `IOCFeedMetadata`, `UpdateResult` interfaces
- **Public key module** (`src/ioc/public-key.ts`): bundled Ed25519 public key PEM, default feed URL, staleness threshold constants
- **Maintainer scripts**: `scripts/generate-feed-keypair.mjs` (generates Ed25519 keypair), `scripts/sign-feed.mjs` (produces detached base64 `.sig` file)
- 33 new tests in `src/ioc/updater.test.ts`: signature verification (valid, tampered, wrong key, malformed, wrong length), deserialization (RegExp, BinaryPattern, flags, empty), merge (all 8 fields, dedup, bundled preservation), staleness (missing, fresh, old, custom threshold, malformed), cached feed (missing, valid, tampered+deleted), fetch cycle (success, network error, bad sig, version downgrade, staleness skip, force bypass), init integration (bundled fallback, idempotent, reset)
- `feed-signing-key.pem` added to `.gitignore`
- Test suite now at 374 tests across 35 test files

#### Missing Design-Spec Checks (11 new checks, 1 new category)
- **SKL-011** (Dependency Audit): checks skill `package.json` deps against known malicious packages (`event-stream`, `flatmap-stream`, etc.) and malicious publishers; warns on missing lockfile (warning)
- **SKL-012** (Code Complexity): cyclomatic complexity per function via Babel AST traversal; flags functions exceeding threshold of 15 decision points (info)
- **IOC-007** (Binary Pattern Match): YARA-like byte/regex patterns on skill files — detects embedded ELF, Mach-O 64/32-bit, PE/DOS binaries, NUL-padding shellcode markers, and packed JS eval wrappers (critical)
- **IOC-008** (VirusTotal Cross-Reference): SHA-256 hashes skill files and checks against VirusTotal API; opt-in via `VIRUSTOTAL_API_KEY` env var, passes gracefully when no key is set (critical)
- **NET-005** (Active Connection Monitoring): parses `netstat`/`ss` output for ESTABLISHED connections and cross-references IPs against C2 database; darwin/linux only (critical)
- **RUN-005** (Process Ancestry Analysis): walks PPID chain (max 5 levels) for agent processes, flags suspicious parents like `curl`, `wget`, `nc`, `python`, `bash -c`; darwin/linux only (warning)
- **POL-001** (Exec Approval Required): verifies tool execution requires user approval — detects `auto_approve: true`, `execApproval: false`, and `AGENT_AUTO_APPROVE_TOOLS` env var (warning)
- **POL-002** (Log Redaction): verifies logging has secret redaction configured when logging is enabled (warning)
- **POL-003** (Session Credential Permissions): `stat()` on session/token/auth/credential files for 0600 permissions; darwin/linux only (warning)
- **POL-004** (Sandbox Policy Enforcement): when sandbox is enabled, verifies it has ≥2 substantive constraints (exec, filesystem, network restrictions) (warning)
- **POL-005** (Plaintext Credential Files): scans `.npmrc`, `.netrc`, `.pgpass`, `.my.cnf`, `.s3cfg`, `credentials`, `secrets.txt`, `.boto`, `.pypirc`, `.authinfo` against `API_KEY_PATTERNS` (critical)
- **`binaryPatterns`** field added to `IOCDatabase` interface with 6 seed patterns (ELF, Mach-O 64-bit, Mach-O 32-bit, PE/DOS, NUL shellcode, packed JS)
- **`policy`** check category added — `src/checks/policy/` with 5 checks and barrel index
- 34 new tests: `skill-checks.test.ts` (7), `ioc-checks.test.ts` (6), `network-checks.test.ts` (2), `runtime-checks.test.ts` (3), `policy-checks.test.ts` (16)
- Test suite now at 341 tests across 34 test files
- Total security checks: 98

#### HTML Output Format
- **HTML reporter** (`src/reporting/html.ts`): self-contained, browser-viewable scan report with all CSS inlined — no external dependencies or JavaScript frameworks required
- Color-coded severity badges (critical=#dc2626, warning=#d97706, info=#2563eb), grade-colored score display (A/B=green, C=amber, D/F=red), summary cards row, per-agent findings tables with striped rows, passed checks lists, and evidence file:line references
- Responsive layout using CSS grid — works on mobile (collapses to 2-column cards and single-column passed lists at 600px)
- XSS-safe HTML escaping for all user-controlled content (messages, evidence, config values)
- `--format html` available on `vaso scan` and `vaso mcp scan` commands
- `'html'` added to `OutputFormat` type union
- 11 tests in `src/reporting/html.test.ts`: HTML structure, content rendering, severity labels, agent name display, evidence rendering, HTML escaping, empty agents, fixable indication, metadata, format property
- Test suite now at 307 tests across 29 test files

#### Per-Agent Scanning for OpenClaw Multi-Agent Installations
- **`agentName`** and **`skillsDirs`** fields added to `AgentInstallation` — `agentName` identifies sub-agent definitions (e.g. `"researcher"`, `"coder"`), `skillsDirs` supports multiple skill directories (shared + per-agent)
- **OpenClaw adapter** now discovers `agents/` subdirectories within each installation: for each sub-agent, loads agent-specific configs (`agent.yaml`, `agent.json`, `config.yaml`, `config.json`, `.env`), deep-merges with global config (agent overrides global), and emits a separate `AgentInstallation` with merged configs and combined skill directories
- **`deepMerge()`** utility in `src/core/utils.ts`: recursive object merge where override wins for conflicts, arrays from override replace base arrays
- **Terminal reporter** shows `agent: <name>` in scan headers when sub-agents are present
- **`vaso detect`** shows agent name in output and sub-agent count in summary (e.g. `Found 3 agent(s) (2 sub-agent definitions).`)
- **Markdown reporter** includes `(agent: <name>)` in section headers
- **SARIF reporter** includes `agentName` in result properties
- No changes needed to scan engine, check modules, remediation engine, or config writer — they already operate on `AgentInstallation[]` and `ScanContext`

#### Tests
- `src/core/utils.test.ts`: 9 tests covering `getNestedValue`, `setNestedValue`, and `deepMerge` (shallow merge, deep nested merge, override wins, array replacement, immutability, empty objects)
- `src/adapters/openclaw-agents.test.ts`: 5 tests for per-agent discovery (multi-agent detection with config merging and skillsDirs, global-only fallback, agentName correctness, cliBinary/appBundle inheritance, non-directory entry filtering)
- Test suite now at 296 tests across 28 test files

#### Remediation Engine — `vaso fix` Now Works
- **Config writer utilities** (`src/remediation/config-writer.ts`): `updateEnvFile()`, `updateJsonFile()`, `updateYamlFile()`, `updateTomlFile()`, `chmodFile()`, and `updateConfigValue()` dispatcher — handles all 4 config formats with comment/indentation preservation
- **`setNestedValue()`** in `src/core/utils.ts`: write counterpart to `getNestedValue()`, creates intermediate objects as needed
- **Rollback support** (`src/remediation/rollback.ts`): restores files from `~/.vaso/backups/` by timestamp; `vaso fix --rollback` now functional (previously printed "not implemented yet")
- **42 `fix()` methods** across all fixable checks:

  **IronClaw (12 checks)** — 8 automatable, 4 guidance-only:
  - IC-001: `HTTP_HOST=127.0.0.1`
  - IC-003: `ORCHESTRATOR_HOST=127.0.0.1`
  - IC-004: generates random 32-byte hex `GATEWAY_AUTH_TOKEN`
  - IC-005: `SANDBOX_ENABLED=true`
  - IC-006: `SANDBOX_POLICY=restricted`
  - IC-007: `AGENT_AUTO_APPROVE_TOOLS=false`
  - IC-008: `ALLOW_LOCAL_TOOLS=false`
  - IC-012: `SANDBOX_AUTO_PULL=false`
  - IC-002, IC-009, IC-010, IC-011: return manual action guidance

  **Config (7 checks)** — 6 automatable, 1 file permission:
  - CFG-001: `gateway.host=127.0.0.1`
  - CFG-005: adds `safeBins` allowlist with 8 safe defaults
  - CFG-008: `sandbox=true`
  - CFG-010: adds `rateLimit` (60 req/min)
  - CFG-012: `auth.bypass=false`
  - CFG-013: `dm.policy=restricted`
  - CFG-003: `chmod 600` on all overly-permissive config files

  **Nanobot (10 checks)** — 5 automatable, 5 guidance-only:
  - NB-003: `restrictToWorkspace=true`
  - NB-004: adds 13-entry ExecTool `denyList` (rm, curl, wget, etc.)
  - NB-005: adds SSRF-blocking `blockedHosts` (localhost, private IPs, metadata endpoint)
  - NB-009: `sessions.encryption=true`
  - NB-011: adds `rateLimit` (30/min, 500/hr)
  - NB-001, NB-002, NB-008, NB-010, NB-012: return manual action guidance

  **ZeroClaw (13 checks)** — 7 automatable, 1 file permission, 5 guidance-only:
  - ZC-001: `secrets.encrypt=true`
  - ZC-003: `security.allow_public_bind=false`
  - ZC-004: `require_pairing=true`
  - ZC-005: `autonomy.level=supervised`
  - ZC-006: `workspace_only=true`
  - ZC-008: `skills.open_install=false`
  - ZC-014: `runtime.sandbox=firejail`
  - ZC-013: `chmod 600` on `.secret_key`
  - ZC-002, ZC-007, ZC-009, ZC-011, ZC-012: return manual action guidance

#### Tests
- `src/remediation/config-writer.test.ts`: 16 tests covering all 5 writer functions, format preservation, and dispatcher routing
- `src/remediation/remediation.test.ts`: 17 integration tests — end-to-end fix→verify cycles for representative checks from each agent category, guidance-only checks, file permissions, and rollback
- Test suite now at 282 tests across 26 test files

### Changed

- **Adapter `detect()` signature**: `AgentAdapter.detect()` now returns `Promise<AgentInstallation[]>` instead of `Promise<AgentInstallation | null>`, enabling adapters to report multiple installations (e.g. different users or profiles)
- **`AdapterRegistry.detectAll()`** accepts optional `DetectOptions` and flatMaps adapter results
- **NanoClaw/PicoClaw adapters**: updated to new `detect()` signature (return `[]`/`[installation]`)
- **Shared utilities extracted**: `getNestedValue()` (from 13 files), `getSkillFiles()` (from 10 files), and `pathExists()` (from 3 adapters) consolidated into `src/core/utils.ts` to eliminate duplication
- **CFG-001 (Gateway Binding)**: now detects IPv6 wildcard binds (`[::]`, `::`) alongside `0.0.0.0`, and checks `server.host` config path for ZeroClaw TOML support

### Added

#### IronClaw Agent Support
- **IronClaw adapter** (`src/adapters/ironclaw.ts`): detects `~/.ironclaw/` config dir with `.env`, `config.toml`, `settings.json`, `mcp-servers.json`; CLI binary via `~/.cargo/bin/ironclaw` or `which` fallback; gateway extraction from env vars and TOML `[gateway]` section
- **IC-001** (HTTP Webhook Public Bind): detects `HTTP_HOST=0.0.0.0` default on port 8080 (critical)
- **IC-002** (No TLS on Listeners): checks all 3 listeners (gateway/webhook/orchestrator) for TLS cert configuration (critical)
- **IC-003** (Orchestrator Public Bind): detects `ORCHESTRATOR_HOST=0.0.0.0` on gRPC port 50051 (critical)
- **IC-004** (Missing Gateway Auth Token): flags missing/empty `GATEWAY_AUTH_TOKEN` with ephemeral random fallback (warning)
- **IC-005** (Sandbox Disabled): detects `SANDBOX_ENABLED=false` in .env or TOML (critical)
- **IC-006** (Full Access Sandbox Policy): detects `SANDBOX_POLICY=full_access` granting unrestricted system access (critical)
- **IC-007** (Auto-Approve Tools): detects `AGENT_AUTO_APPROVE_TOOLS=true` bypassing all tool approval prompts (critical)
- **IC-008** (Local Tools Bypass): detects `ALLOW_LOCAL_TOOLS=true` allowing tool execution outside sandbox (warning)
- **IC-009** (Secrets Key in .env): detects plaintext `SECRETS_MASTER_KEY` in config files (critical)
- **IC-010** (Telegram Without Owner ID): flags Telegram enabled without `TELEGRAM_OWNER_ID` restriction (warning)
- **IC-011** (Broad Sandbox Domains): detects wildcard patterns in `SANDBOX_EXTRA_DOMAINS` (warning)
- **IC-012** (Docker Auto-Pull No Digest): flags `SANDBOX_AUTO_PULL=true` without `@sha256:` digest pinning (warning)

#### Nanobot Agent Support
- **Nanobot adapter** (`src/adapters/nanobot.ts`): detects `~/.nanobot/config.json`; skills at `workspace/skills/`; memory files (MEMORY.md, HEARTBEAT.md, SOUL.md); gateway from root `host`/`port` (default `0.0.0.0:18790`); CLI binary via `which` fallback
- **NB-001** (Empty Channel allowFrom): detects `channels.*.allowFrom: []` with no access control (critical)
- **NB-002** (Plaintext Secrets): scans config.json for plaintext API keys using `API_KEY_PATTERNS` (critical)
- **NB-003** (Workspace Sandboxing Off): detects `restrictToWorkspace: false` (default) (warning)
- **NB-004** (Weak Shell Filtering): flags ExecTool denylist that is missing, empty, or shorter than 5 entries (critical)
- **NB-005** (No SSRF Protection): detects WebFetchTool without `blockedHosts`/`allowedHosts` restrictions (warning)
- **NB-006** (Heartbeat Injection Risk): flags writable HEARTBEAT.md executed every 30min (warning)
- **NB-007** (Memory Prompt Injection): detects MEMORY.md loaded into system prompt — persistent injection vector (critical)
- **NB-008** (WhatsApp Bridge No Token): flags WhatsApp enabled without `bridge_token` (warning)
- **NB-009** (Unencrypted Sessions): detects session JSONL files stored without encryption (warning)
- **NB-010** (Cron Arbitrary Channels): flags cron jobs targeting wildcard channels/recipients (warning)
- **NB-011** (No Rate Limiting): detects missing rate limiting on channels (warning)
- **NB-012** (ClawHub via npx): flags skill install via `npx` — supply chain risk (warning)

#### ZeroClaw Agent Support
- **ZeroClaw adapter** (`src/adapters/zeroclaw.ts`): detects `~/.zeroclaw/` with `config.toml`, `auth-profiles.json`; skills at `workspace/skills/`; CLI binary via `~/.cargo/bin/zeroclaw` or `which`; gateway from TOML `[server]` or `[gateway]` section (default port 3000); credential paths include `.secret_key`
- **ZC-001** (Plaintext API Keys): detects `secrets.encrypt=false` with API keys in config (critical)
- **ZC-002** (Legacy XOR Encryption): detects `enc:` prefix values — trivially reversible XOR cipher (critical)
- **ZC-003** (Public Bind No Tunnel): detects `allow_public_bind=true` + `tunnel.provider=none` (critical)
- **ZC-004** (Pairing Disabled): detects `require_pairing=false` allowing unauthenticated device connections (warning)
- **ZC-005** (Full Autonomy Mode): detects `autonomy.level=full` bypassing all approval gates (critical)
- **ZC-006** (Unrestricted Filesystem): detects `workspace_only=false` allowing access beyond workspace (warning)
- **ZC-007** (Wildcard Channel Users): detects `"*"` in `allowed_users` for any channel (critical)
- **ZC-008** (Open Skills Enabled): flags `skills.open_install=true` — supply chain risk via public repos (warning)
- **ZC-009** (Missing WhatsApp App Secret): detects webhooks accepted without HMAC signature verification (warning)
- **ZC-010** (Composio Integration): flags 1000+ OAuth apps attack surface when enabled (info)
- **ZC-011** (Browser No Domain Allowlist): detects browser tool without `allowed_domains` (warning)
- **ZC-012** (HTTP Tool No Domain Filter): detects HTTP request tool without domain restrictions (warning)
- **ZC-013** (.secret_key Permissions): checks file mode is 0600; linux/darwin only (critical)
- **ZC-014** (No OS-Level Sandbox): detects `runtime.kind=native` without Firejail/Bubblewrap/Landlock (warning)

#### Infrastructure
- **TOML config parsing**: added `smol-toml` dependency; `.toml` format detection, parsing, and fallback in `config-loader.ts`; `'toml'` added to `ParsedConfig.format` union
- **Type extensions**: `AgentType` union extended with `'ironclaw' | 'nanobot' | 'zeroclaw'`; `CheckCategory` union extended with `'ironclaw' | 'nanobot' | 'zeroclaw'`
- **Telegram Bot token pattern** added to `API_KEY_PATTERNS` in `src/core/patterns.ts`
- **`src/core/utils.ts`**: shared `getNestedValue()`, `getSkillFiles()`, `pathExists()` — imported by 23+ check and adapter files

#### Tests & Fixtures
- 3 adapter unit tests: `ironclaw.test.ts` (9 tests), `nanobot.test.ts` (8 tests), `zeroclaw.test.ts` (8 tests)
- 3 check unit tests: `ironclaw-checks.test.ts`, `nanobot-checks.test.ts`, `zeroclaw-checks.test.ts`
- TOML parsing test added to `config-loader.test.ts`
- Test fixtures for all 3 agents: insecure configs (triggering all agent-specific checks), secure configs, malicious and safe skill directories
- 3 Dockerfiles: `ironclaw.Dockerfile`, `nanobot.Dockerfile`, `zeroclaw.Dockerfile`
- 3 integration test suites: `ironclaw.integration.test.ts`, `nanobot.integration.test.ts`, `zeroclaw.integration.test.ts`
- Test suite now at 249 tests across 24 test files
- Total security checks: 83 (45 existing + 12 IC + 12 NB + 14 ZC) — all 45 existing checks automatically apply to new agents (no `supportedAgents` filter)

### Added

#### Multi-user Scanning
- `--all-users` flag on `vaso scan` and `vaso detect` — when running as root/sudo, enumerates all user home directories (`/Users/*` on macOS, `/home/*` + `/root` on Linux) to find agent installations across all accounts
- `DetectOptions` interface in `src/adapters/adapter.ts` with `allUsers` flag, threaded from CLI through engine to adapters
- `getUserHomeDirs()` helper (exported from OpenClaw adapter for testability) — excludes `Shared`, `Guest`, `.localized`

#### OpenClaw Detection Enhancements
- **`OPENCLAW_PROFILE` support**: reads the `OPENCLAW_PROFILE` env var and searches `~/.openclaw-{PROFILE}` directories alongside the default `~/.openclaw`; stored in `AgentInstallation.profile`
- **CLI binary detection**: checks system paths (`/usr/local/bin`, `/opt/homebrew/bin`, `/usr/bin`), user-relative paths (`~/.volta/bin`, `~/.local/bin`, `~/.nvm/current/bin`, `~/bin`), and `which openclaw` fallback; stored in `AgentInstallation.cliBinary`
- **macOS `.app` bundle detection**: checks `/Applications/OpenClaw.app`; stored in `AgentInstallation.appBundle`
- **Minimal installation reporting**: returns an installation entry when only a CLI binary or `.app` bundle is found (no config files), enabling `vaso detect` to report partially-installed agents

#### Types
- `AgentInstallation`: added `profile`, `user`, `appBundle`, `cliBinary` fields
- `ScanOptions`: added `allUsers` field

#### CLI & Reporting
- `vaso detect` output now shows CLI binary path, app bundle path, user, and profile when present
- Terminal scan report shows `(user: X, profile: Y)` in agent headers when multi-user or profile data is available

#### Tests
- 12 new unit tests in `src/adapters/openclaw.test.ts`: default detection, profile-aware detection, CLI binary discovery (system paths, `which` fallback), `.app` bundle detection, minimal installation, `OPENCLAW_HOME` support, `getUserHomeDirs()` behavior
- Updated mock adapter in `src/core/engine.test.ts` to match new `detect()` signature
- Test suite now at 272 tests (170 unit + 102 integration) across 24 test files

### Fixed

- **TypeScript type error in `headerParts`**: `detect.ts` and `terminal.ts` inferred `headerParts` as `AgentType[]` from `[inst.agent]`, causing template literal strings (`user: …`, `profile: …`) to fail type-checking; added explicit `string[]` annotation to both
- **testcontainers API compatibility**: `builtImage.imageName` returns an object in testcontainers v11, not a string — use `.string` property when constructing `GenericContainer`
- **SKL-002 (Obfuscated Code)**: Entropy-only detection missed hex escape sequences (3.16 bits/char) and base64 strings (5.13 bits/char) below the 5.5 threshold; added pattern-based detection for hex escape chains, long base64 strings, `String.fromCharCode`, and `atob()`
- **RS-005 regex false positive**: Pattern `/\bSocket\b.*\bsubprocess|exec|spawn\b/i` was parsed as three ungrouped alternations, causing `exec` to match "execution" in comments; fixed to `/\bSocket\b.*\b(?:subprocess|exec|spawn)\b/i`
- **PicoClaw adapter**: `getGatewayInfo()` returned `undefined` unconditionally and `detect()` never populated `gateway` on the installation; implemented gateway extraction matching the OpenClaw adapter pattern
- **PicoClaw secure fixture**: Calculator skill used `Function()` (flagged as critical by SKL-003); replaced with safe token-based arithmetic; added `workspace` and `safeBins` config keys to pass CFG-005/CFG-006

### Added

#### MCP Server Security Scanning
- **MCP discovery engine** (`src/mcp/discovery.ts`): scans all known config locations for Claude Desktop (macOS/Linux/Windows), Claude Code (`~/.claude/mcp.json`, `.mcp.json`), Cursor, Windsurf, and VS Code; parses `mcpServers` blocks with stdio/SSE/streamable-HTTP transport inference
- **MCP source resolver** (`src/mcp/source-resolver.ts`): infers package names from `npx`/`uvx`/`node` commands, resolves local source paths for AST analysis
- **`vaso mcp scan`** command: standalone MCP security scan with `--format`, `--output`, and `--path` options
- **`vaso mcp list`** command: inventory all discovered MCP server configurations
- **MCP-001** (Config Discovery): inventories all configured MCP servers across all agent configs (info)
- **MCP-002** (Transport Security): detects SSE/HTTP on 0.0.0.0, missing TLS, `--no-tls` flags (critical)
- **MCP-003** (Credential Exposure): detects plaintext API keys and high-entropy secrets in env blocks; reuses shared `API_KEY_PATTERNS` and Shannon entropy analysis (critical)
- **MCP-004** (Overprivileged Tools): detects exec/shell/write capabilities in server source via AST analysis (critical)
- **MCP-005** (Tool Input Injection): detects unsanitized LLM/user input flowing to exec, spawn, eval, SQL, and file write sinks (critical)
- **MCP-006** (Data Exfiltration Risk): detects source-to-sink data flow and suspicious network calls in server source via AST (critical)
- **MCP-007** (Prompt Injection via Tool Results): detects raw external HTTP/file content returned unsanitized in tool results; accounts for sanitization presence (warning)
- **MCP-008** (Server Provenance): checks package names against IOC database for typosquatting (Levenshtein distance), malicious publishers, and malicious domain/name patterns (warning/critical)
- **MCP-009** (Permission Scope): detects disproportionate resource access — admin naming, world-writable permissions, root filesystem globbing, Docker privileged mode (warning)
- **MCP-010** (Rug Pull Risk): detects unpinned `npx`/`uvx` versions and auto-install flags that enable supply chain attacks (warning)
- Added `'mcp'` to `AgentType` and `CheckCategory` type unions
- Added `mcpConfigs` and `mcpServerSources` fields to `ScanContext`
- Added `scanMCP()` method to `ScanEngine` for standalone MCP scanning
- Added `trustedMCPPackages` (16 known packages) to IOC database for typosquatting detection
- Extracted shared `API_KEY_PATTERNS` to `src/core/patterns.ts` for reuse across CFG-002 and MCP-003
- 34 new tests: 6 for MCP discovery, 20 for MCP checks (insecure + secure cases for each), 8 for MCP command (`runMCPScan`/`runMCPList`)
- Test fixtures: insecure/secure Claude Desktop configs, vulnerable/safe MCP server source files

#### MCP Integration Testing
- **MCP Dockerfile** (`testing/docker/agents/mcp.Dockerfile`): copies MCP config and vulnerable server source for Docker-based end-to-end tests
- **MCP integration test** (`testing/integration/mcp.integration.test.ts`): insecure scenario asserts all 10 MCP checks (MCP-001 through MCP-010) with correct severities, low score, and failing grade; secure scenario asserts MCP-002, MCP-003, MCP-010 pass with high score and passing grade
- **`mcp-insecure` and `mcp-secure`** services added to `testing/docker-compose.yml`
- **`command` option** added to `VasoScanOptions` in `testing/integration/helpers.ts` to support custom CLI subcommands (e.g., `['mcp', 'scan', '--path', '/mcp/config.json']`); backward-compatible — defaults to `['scan']`
- **MCP command unit test** (`src/commands/mcp.test.ts`): 8 tests covering `runMCPScan` (path discovery, platform discovery, no servers, critical exit code) and `runMCPList` (JSON output, terminal output, no servers, platform discovery)

#### Docker Integration Testing Infrastructure
- **testcontainers** integration for programmatic Docker-based integration tests driven by vitest
- Multi-stage base Dockerfile (`testing/docker/base.Dockerfile`) — builds VASO in `node:20-slim`, copies only runtime artifacts to final image
- Agent-specific Dockerfiles for OpenClaw, NanoClaw, PicoClaw, and multi-agent scenarios with `ARG SCENARIO` for insecure/secure switching
- Fixture files for all three agents:
  - **OpenClaw insecure**: triggers CFG-001, CFG-002, CFG-004, CFG-007, CFG-008, CFG-009, CFG-010, CFG-012, CFG-013, CFG-014, CFG-015, SKL-001, SKL-002, SKL-003, SKL-005, SKL-007, IOC-001, IOC-002, IOC-005
  - **NanoClaw insecure**: triggers CFG-001, CFG-008, CFG-012, CFG-013, CFG-014, SKL-003, IOC-001
  - **PicoClaw insecure**: triggers CFG-001, CFG-002, CFG-008, CFG-009, CFG-012, IOC-002
  - Secure variants for all agents with hardened configs and benign skills
- Test helpers (`testing/integration/helpers.ts`): `buildBaseImage()`, `runVasoScan()`, `findCheck()`, `getAgentResult()`, `expectCheckFailed()`, `expectCheckPassed()`
- 6 integration test suites: `openclaw.integration.test.ts`, `nanoclaw.integration.test.ts`, `picoclaw.integration.test.ts`, `multi-agent.integration.test.ts`, `scoring.integration.test.ts`, `mcp.integration.test.ts`
- Separate vitest config (`testing/vitest.config.integration.ts`) with 120s test timeout, 180s hook timeout
- Docker Compose file (`testing/docker-compose.yml`) with 11 services for manual testing
- GitHub Actions CI workflow (`.github/workflows/integration-tests.yml`) — runs integration tests after unit tests pass
- npm scripts: `test:integration`, `test:all`, `docker:build-base`
- `.dockerignore` for optimized Docker build context

## [0.1.0] - 2026-02-20

Initial release of VASO with full scan engine, 39 security checks, 3 agent adapters, and 5 output formats.

### Added

#### Core Engine
- Scan engine with concurrent check execution via `Promise.allSettled`
- Auto-detection of installed AI agent frameworks
- Scoring system: 100-point scale with letter grades (A-F), -12 per critical, -5 per warning
- Check registry with filtering by category, agent, and platform
- Config loader supporting JSON, YAML, and `.env` formats
- Differential scanning with baseline save/load/diff (`--save-baseline`, `--diff`)

#### CLI
- `vaso detect` command to enumerate installed AI agents without running security checks; supports `--agent`, `--format` (terminal/json), and `--verbose` options
- `vaso scan` command with auto-detect, `--agent`, `--format`, `--output` options
- `vaso fix` command with `--dry-run` and `--yes` modes
- `vaso update` command to reload IOC database
- Exit code 1 when critical findings are detected

#### Agent Adapters
- **OpenClaw** adapter: detects `$OPENCLAW_HOME`, `~/.openclaw`, `~/.clawdbot`, `~/.moltbot`, `/etc/openclaw`; parses `openclaw.json`, `config.yaml`, `gateway.yaml`, `.env`
- **NanoClaw** adapter: detects `~/.nanoclaw.env`, `~/.config/nanoclaw/`
- **PicoClaw** adapter: detects `~/.picoclaw/config.json`, `~/.picoclaw/auth.json`

#### Configuration Checks (15)
- **CFG-001**: Gateway binding to 0.0.0.0 (critical)
- **CFG-002**: API key exposure — 9 patterns including `sk-`, `AKIA`, `ghp_`, `gho_`, `glpat-`, `xoxb-`, `xoxp-`, private keys (critical)
- **CFG-003**: Overly permissive file permissions on config files (warning)
- **CFG-004**: TLS/SSL not configured (warning)
- **CFG-005**: Missing shell command allowlist (`safeBins`) (warning)
- **CFG-006**: No workspace directory restriction (warning)
- **CFG-007**: Webhook endpoints without authentication (warning)
- **CFG-008**: Sandbox disabled (critical)
- **CFG-009**: Default or weak credentials in auth config (critical)
- **CFG-010**: No rate limiting configured (warning)
- **CFG-011**: Node.js CVE-2026-21636 version check (warning)
- **CFG-012**: Authentication bypass enabled (critical)
- **CFG-013**: DM policy set to open (warning)
- **CFG-014**: Permissive tool policy (warning)
- **CFG-015**: mDNS full broadcast enabled (info)

#### Skill Code Analysis Checks (10)
- **SKL-001**: Data exfiltration — AST-based source-to-sink data flow tracing (critical)
- **SKL-002**: Obfuscated code — Shannon entropy analysis, threshold >5.5 bits/char (warning)
- **SKL-003**: Eval/exec usage — detects `eval()`, `new Function()`, `child_process.exec()` (critical)
- **SKL-004**: Curl-pipe execution — `curl|sh`, `wget|bash` patterns (critical)
- **SKL-005**: Reverse shell patterns — 7 detection patterns ported from B@dskills threat model (critical)
- **SKL-006**: Credential harvesting — `.ssh`, `.aws`, `.env` file access via AST + pattern matching (critical)
- **SKL-007**: Prompt injection in SKILL.md — instruction override and delimiter escape patterns (warning)
- **SKL-008**: Suspicious network calls — non-localhost, non-HTTPS connections via AST (warning)
- **SKL-009**: Crypto wallet targeting — wallet address patterns and crypto API usage (warning)
- **SKL-010**: Unauthorized filesystem access — file operations outside workspace via AST (warning)

#### IOC Checks (6)
- **IOC-001**: C2 IP detection — 5 known ClawHavoc campaign IPs (critical)
- **IOC-002**: Malicious domain detection — 9 known payload hosting and exfil domains (critical)
- **IOC-003**: File hash matching — SHA-256 comparison against 4 known AMOS stealer variants (critical)
- **IOC-004**: Malicious publisher detection — 9 blacklisted publishers from ClawHavoc/Bloom campaigns (critical)
- **IOC-005**: Typosquatting detection — Levenshtein distance <= 2 against 20 trusted skill names (warning)
- **IOC-006**: Malicious skill name patterns — 10 regex patterns for known malicious naming conventions (warning)

#### Network Checks (4)
- **NET-001**: Gateway internet exposure — 0.0.0.0 or :: binding detection (critical)
- **NET-002**: WebSocket origin validation — CVE-2026-25253 check (critical)
- **NET-003**: Reverse proxy bypass — `trustProxy` without IP restriction (warning)
- **NET-004**: Port scan for agent services — checks ports 18789, 18790, 3000, 8080, 8443 (info)

#### Runtime Checks (4)
- **RUN-001**: Unauthorized LaunchAgents (macOS) / systemd services (Linux) (warning)
- **RUN-002**: Suspicious cron entries referencing agent paths (warning)
- **RUN-003**: VS Code extension trojans — known malicious extension ID detection (critical)
- **RUN-004**: Docker socket permission check (warning)

#### Analyzers
- AST analyzer using `@babel/parser` + `@babel/traverse` with scope-aware variable tracking and source-to-sink data flow tracing
- Pattern engine with 40+ regex rules across 8 categories: reverse-shell, curl-pipe, credential-harvest, exfiltration, prompt-injection, crypto-wallet, obfuscation, code-exec
- Shannon entropy analyzer for detecting obfuscated/packed code blocks

#### IOC Database
- Bundled threat intelligence: 5 C2 IPs, 9 malicious domains, 4 file hashes, 9 malicious publishers, 10 malicious name patterns, 20 trusted skill names
- Reloadable via `vaso update`

#### Remediation Engine
- Automatic backup to `~/.vaso/backups/{timestamp}/` before modifications
- Dry-run mode for previewing fixes
- Auto-fix support for: gateway rebinding, file permissions, shell allowlist, sandbox enable, auth bypass disable, rate limiting, DM policy

#### Output Formats
- **Terminal**: Styled output with chalk, color-coded by severity
- **JSON**: Structured output with per-agent scores and check results
- **SARIF**: v2.1.0 for GitHub Code Scanning and GitLab SAST integration
- **Markdown**: Tables and sections for PR comments and documentation

#### CI/CD
- GitHub Actions workflow (`.github/workflows/vaso-scan.yml`) with SARIF upload and artifact storage
- `bin/vaso-quick.sh`: Zero-dependency Bash script for 5 critical checks without Node.js

#### Test Suite
- 158 tests across 17 test files
- Coverage: core engine, scoring, config loader, check registry, all 15 config checks, 10 MCP checks, MCP discovery, MCP command, AST analyzer, pattern engine, entropy analyzer, IOC database, typosquatting, SARIF output, markdown output, baseline diffing, detect command

[0.2.1]: https://github.com/vulnex/vaso/releases/tag/v0.2.1
[0.2.0]: https://github.com/vulnex/vaso/releases/tag/v0.2.0
[0.1.0]: https://github.com/vulnex/vaso/releases/tag/v0.1.0
