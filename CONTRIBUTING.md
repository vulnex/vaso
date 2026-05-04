# Contributing to VASO

Thanks for your interest. VASO is an agent-agnostic security scanner — contributions that add coverage for new agent frameworks, new check types, or new threat-intel sources are especially welcome.

For security vulnerabilities **in VASO itself**, do not open a public issue — see [SECURITY.md](SECURITY.md).

## Development Setup

Requires Node.js 20+.

```bash
git clone https://github.com/vulnex/vaso.git
cd vaso
npm install
npm run build      # tsup → dist/cli.js
npm test           # unit tests (vitest)
npm run lint       # tsc --noEmit
```

For the integration suite (Docker required) and end-to-end fixtures:

```bash
npm run test:e2e
npm run test:integration
npm run test:all
```

## What Contributions Are In Scope

| Type | Where it lives | Examples |
|------|----------------|----------|
| **New check** | `src/checks/<category>/` | New CFG/SKL/MCP/coding-agent rule for a known threat |
| **New agent adapter** | `src/adapters/` | Support for a new agent framework or coding CLI |
| **New output format** | `src/reporting/` | Reporter for a SIEM, ticketing system, etc. |
| **IOC feed signer / source** | `src/ioc/` | New threat-intel source with signature verification |
| **Bug fix** | Anywhere | Correctness, false-positive reduction, perf |

For larger changes (new check category, new core abstraction), please open an issue first to align on scope.

## Adding a Security Check

The most common contribution. Steps:

1. Pick a category in `src/checks/` (or propose a new one).
2. Create `<id>-<short-name>.ts` (e.g., `cfg-025-something.ts`) exporting a `CheckModule`:
   ```ts
   import type { CheckModule } from '../../core/types.js';

   export const cfg025: CheckModule = {
     id: 'CFG-025',
     name: 'Short human-readable name',
     category: 'config',
     severity: 'critical',  // or 'warning' | 'info'
     description: 'One-sentence description of what this catches.',
     supportedAgents: ['openclaw', 'nanoclaw'],     // optional allowlist
     excludedAgents: CODING_AGENTS,                  // optional blocklist
     supportedPlatforms: ['darwin', 'linux'],        // optional
     run(context) {
       // Return CheckResult — see src/core/types.ts
     },
     fix(context) {
       // Optional — only if the issue is auto-remediable
     },
   };
   ```
3. Register it in the category's `index.ts`.
4. **Add a unit test** in the same directory: `<id>-<short-name>.test.ts`. Cover the passing case, the failing case, and at least one edge case (missing config, malformed input, etc.).
5. Update `CHANGELOG.md` under `[Unreleased]`.
6. If the check increases the total count, update the count in `CLAUDE.md` and `README.md`.

Check IDs follow the pattern `<CATEGORY>-<NNN>`. Reserve a sequential ID; don't reuse retired ones.

## Adding an Agent Adapter

Less common but well-supported:

1. Create `src/adapters/<agent>.ts` implementing the `AgentAdapter` interface.
2. Register it in `src/cli.ts` via `adapterRegistry.register()`.
3. Add a `getZoneGraph()` if the agent has a non-trivial trust topology (otherwise the default 4-zone fallback is used).
4. Add detection tests in `src/adapters/<agent>.test.ts`.
5. If the agent is an interactive coding CLI (different threat model from autonomous server agents), add it to the `CODING_AGENTS` runtime constant in `src/core/types.ts` so the server-only checks correctly skip it.
6. Document the adapter in `CLAUDE.md` and `README.md`.

See [doc/development-guide.md](doc/development-guide.md) for the full reference.

## Code Style

- TypeScript strict mode, ESM only (`"type": "module"`).
- Don't add comments that just restate what the code does. Comment only the *why* when it's non-obvious.
- No `eval`, no dynamic `require`, no execution of scanned code. VASO is static-analysis only — this is a hard constraint.
- No outbound network calls during scans. The only allowed network access is in `vaso update` and only against signed IOC feeds.
- Prefer parsing libraries (`yaml`, `smol-toml`, `@babel/parser`) over hand-rolled regex when reading user-supplied config.
- New code paths must have unit tests. PRs that don't add tests for new behavior will be asked to add them.

## Commit Style

Imperative subject line, ≤ 70 chars. Add a body only when the *why* needs explaining. Recent examples from the log:

```
Add OpenCode agent adapter and 12 OPC-* security checks
Codex: extract active model from latest session jsonl when config absent
Fix false-positive agent detection from null directory listings
```

No Conventional Commits prefix is used; please match existing style.

## Pull Request Checklist

- [ ] Tests added or updated (`npm test` passes)
- [ ] `npm run lint` passes (no type errors)
- [ ] `npm run build` produces a clean `dist/cli.js`
- [ ] `CHANGELOG.md` updated under `[Unreleased]`
- [ ] If check count or adapter list changed: `README.md` and `CLAUDE.md` updated to match
- [ ] No bundled secrets, signing keys, or proprietary IOC data
- [ ] No outbound network calls in scan paths

## Plugin Authors

Custom checks, reporters, or adapters that don't belong in the core repo can ship as user plugins in `~/.vaso/plugins/`. See [doc/development-guide.md](doc/development-guide.md) for the plugin API and `examples/plugins/` for working examples.

## Questions

Open an issue at [github.com/vulnex/vaso/issues](https://github.com/vulnex/vaso/issues) with the `question` label.
