# VASO Example Plugins

Example user plugins demonstrating the VASO plugin API. Each file is a standalone `.mjs` module that can be dropped into `~/.vaso/plugins/` to extend VASO with custom checks, reporters, and agent adapters.

## Installation

```bash
# Copy one or more plugins to the VASO plugins directory
mkdir -p ~/.vaso/plugins
cp examples/plugins/env-hygiene-check.mjs ~/.vaso/plugins/

# Verify it loaded
vaso ext list
```

## Examples

| File | Difficulty | Demonstrates |
|------|-----------|--------------|
| `env-hygiene-check.mjs` | Simple | `api.registerCheck()` — single check with evidence collection |
| `csv-reporter.mjs` | Simple | `api.registerReporter()` — custom output format |
| `compliance-audit-checks.mjs` | Medium | `api.registerChecks()` — batch registration, `fix()` method, shared helpers |
| `custom-agent-adapter.mjs` | Advanced | All three APIs — adapter, check, and reporter in one plugin |

### env-hygiene-check.mjs

Registers **USR-001** (warning) — detects development/debug environment patterns in agent configs such as `NODE_ENV=development`, `DEBUG=true`, localhost references, and private IPs. Scans both parsed config data (structured walk) and raw text (line-by-line).

### csv-reporter.mjs

Registers a **csv** output format for `vaso scan --format csv`. Produces RFC 4180-compliant CSV with one row per evidence item, a header row, and a summary row at the bottom.

### compliance-audit-checks.mjs

Registers three compliance checks using batch registration:
- **USR-010** (critical): Audit logging must be enabled
- **USR-011** (warning): Log rotation should be configured
- **USR-012** (warning): Data retention policy should be defined

USR-010 includes a `fix()` method that returns remediation guidance.

### custom-agent-adapter.mjs

A complete plugin demonstrating all three APIs for a fictional "ToolForge" agent framework:
- **Adapter**: Detects `~/.toolforge/`, reads config, discovers tools directory
- **USR-020** (warning): Validates ToolForge sandbox config (agent-scoped via `supportedAgents`)
- **summary-line** reporter: Single-line output for CI/CD — `VASO: 85/100 (B) | 0 critical, 2 warning, 1 info | openclaw`

## Plugin Structure

Every VASO plugin exports a default object with `meta` and `register`:

```js
export default {
  meta: {
    name: 'my-plugin',
    version: '1.0.0',
    description: 'What it does',
  },
  register(api) {
    api.registerCheck({ /* ... */ });
    api.registerReporter('format', () => ({ /* ... */ }));
    api.registerAdapter({ /* ... */ });
  },
};
```

## Check ID Convention

User plugin checks should use the `USR-` prefix to avoid collisions with built-in VASO checks (which use `CFG-`, `SKL-`, `IOC-`, `NET-`, `RUN-`, `POL-`, `MCP-`).

## No External Dependencies

All example plugins use only Node.js built-in modules (`node:fs`, `node:path`, `node:os`). User plugins can import npm packages if needed, but keeping plugins dependency-free makes them easier to distribute.
