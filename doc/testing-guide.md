# VASO Testing Guide

Guide for running, writing, and maintaining VASO's test suites — unit tests and Docker-based integration tests.

## Test Suites Overview

| Suite | Command | What it tests | Duration |
|-------|---------|---------------|----------|
| Unit | `npm test` | Individual components in isolation | ~1s |
| Integration | `npm run test:integration` | End-to-end scans in Docker containers | ~2-5 min |
| All | `npm run test:all` | Unit then integration | ~3-6 min |

## Unit Tests

Unit tests live alongside source files in `src/` and use [vitest](https://vitest.dev/).

### Running

```bash
# Run all unit tests
npm test

# Run a specific test file
npx vitest run src/checks/config/config-checks.test.ts

# Watch mode (re-runs on file changes)
npm run test:watch

# With coverage
npx vitest run --coverage
```

### Test Locations

| Test file | Coverage |
|-----------|----------|
| `src/core/engine.test.ts` | Scan engine, agent filtering, error handling |
| `src/core/check-registry.test.ts` | Check registration, dedup, filtering |
| `src/core/config-loader.test.ts` | JSON, YAML, `.env` parsing |
| `src/core/scoring.test.ts` | Score computation, grading, summaries |
| `src/core/baseline.test.ts` | Differential scan diffing |
| `src/checks/config/config-checks.test.ts` | All 15 config checks |
| `src/analyzers/ast-analyzer.test.ts` | AST data flow, eval/exec, network detection |
| `src/analyzers/pattern-engine.test.ts` | Regex pattern matching across categories |
| `src/analyzers/entropy.test.ts` | Shannon entropy and obfuscation detection |
| `src/ioc/database.test.ts` | IOC database loading and content |
| `src/ioc/typosquat.test.ts` | Levenshtein distance, typosquatting detection |
| `src/reporting/sarif.test.ts` | SARIF v2.1.0 output structure |
| `src/reporting/markdown.test.ts` | Markdown table output |
| `src/commands/detect.test.ts` | Detect command with mocked adapters |
| `src/commands/skill-audit.test.ts` | Skill audit command (path validation, scan, output) |
| `src/remediation/prompt.test.ts` | Interactive TUI prompt (y/n/a/q input handling) |
| `src/remediation/engine.test.ts` | RemediationEngine interactive fix flow |

### Writing Unit Tests

Unit tests mock external dependencies (filesystem, adapters) and test components in isolation:

```typescript
import { describe, it, expect } from 'vitest';
import { cfg001 } from './cfg-001-gateway-binding.js';
import type { ScanContext } from '../../core/types.js';

function makeContext(configData: Record<string, unknown>): ScanContext {
  return {
    installation: { agent: 'openclaw', installDir: '/tmp', configFiles: [] },
    configs: [{
      raw: JSON.stringify(configData),
      format: 'json',
      filePath: '/tmp/config.json',
      data: configData,
    }],
    platform: 'linux',
  };
}

describe('CFG-001 Gateway Binding', () => {
  it('fails when gateway is bound to 0.0.0.0', async () => {
    const ctx = makeContext({ gateway: { host: '0.0.0.0' } });
    const result = await cfg001.run(ctx);
    expect(result.passed).toBe(false);
    expect(result.severity).toBe('critical');
  });
});
```

## Integration Tests

Integration tests run VASO inside Docker containers with realistic agent installations. They validate that the full pipeline — adapter detection, config parsing, check execution, and scoring — works end-to-end against known environments.

### Prerequisites

- **Docker** must be running (Docker Desktop on macOS/Windows, Docker Engine on Linux)
- `testcontainers` npm package (installed as a devDependency)

### Running

```bash
# Build the base Docker image first (optional — tests build it automatically)
npm run docker:build-base

# Run integration tests
npm run test:integration

# Run a specific integration test file
npx vitest run --config testing/vitest.config.integration.ts testing/integration/openclaw.integration.test.ts
```

### How It Works

1. **Base image** (`testing/docker/base.Dockerfile`) builds VASO in a multi-stage Docker build:
   - Stage 1: `node:20-slim` installs dependencies and runs `npm run build`
   - Stage 2: `node:20-slim` copies only `dist/`, `node_modules/`, `package.json`, and `bin/`

2. **Agent images** extend the base and copy fixture files to the expected detection paths:
   - OpenClaw: `/root/.openclaw/`
   - NanoClaw: `/root/.config/nanoclaw/` + `/root/.nanoclaw.env`
   - PicoClaw: `/root/.picoclaw/`

3. **testcontainers** starts each container, executes `node dist/cli.js scan --format json` via `exec()`, and captures the JSON output.

4. **Tests** parse the JSON into `ScanResult` and assert on specific check IDs, severities, scores, and grades.

### Directory Structure

```
testing/
  docker/
    base.Dockerfile                 # Multi-stage VASO build
    agents/
      openclaw.Dockerfile           # OpenClaw fixtures
      nanoclaw.Dockerfile           # NanoClaw fixtures
      picoclaw.Dockerfile           # PicoClaw fixtures
      multi.Dockerfile              # All three agents
  fixtures/
    openclaw/
      insecure/                     # Deliberately vulnerable configs + skills
      secure/                       # Hardened configs + benign skills
    nanoclaw/
      insecure/
      secure/
    picoclaw/
      insecure/
      secure/
  integration/
    helpers.ts                      # Test utilities
    openclaw.integration.test.ts
    nanoclaw.integration.test.ts
    picoclaw.integration.test.ts
    multi-agent.integration.test.ts
    scoring.integration.test.ts
  vitest.config.integration.ts      # Separate vitest config with extended timeouts
  docker-compose.yml                # Manual testing shortcut
```

### Test Helper Functions

The `testing/integration/helpers.ts` module provides:

| Function | Purpose |
|----------|---------|
| `buildBaseImage()` | Builds the base Docker image (cached — only builds once per test process) |
| `runVasoScan(options)` | Builds agent image, starts container, runs VASO, returns parsed `ScanResult` |
| `findCheck(result, 'CFG-001')` | Finds a check by ID across all agents |
| `findAllChecks(result, 'CFG-001')` | Finds all occurrences of a check across agents |
| `getAgentResult(result, 'openclaw')` | Gets a specific agent's results |
| `expectCheckFailed(result, 'CFG-001')` | Asserts a check was detected (failed) — throws with details if not |
| `expectCheckPassed(result, 'CFG-001')` | Asserts a check passed — throws with details if not |

### Writing Integration Tests

Integration tests use `beforeAll` to build and run the container once per `describe` block, then assert across multiple `it()` cases:

```typescript
import { describe, it, expect, beforeAll } from 'vitest';
import type { ScanResult } from '../../src/core/types.js';
import { runVasoScan, getAgentResult, expectCheckFailed } from './helpers.js';

describe('MyAgent Insecure', () => {
  let result: ScanResult;

  beforeAll(async () => {
    result = await runVasoScan({
      dockerfile: 'testing/docker/agents/myagent.Dockerfile',
      buildArgs: { SCENARIO: 'insecure' },
    });
  });

  it('should detect the agent', () => {
    const agent = getAgentResult(result, 'myagent');
    expect(agent).toBeDefined();
  });

  it('should detect gateway binding issue (CFG-001)', () => {
    const check = expectCheckFailed(result, 'CFG-001');
    expect(check.severity).toBe('critical');
  });
});
```

### Fixture Design

Each fixture set is designed to trigger (or not trigger) specific checks.

**Insecure fixtures** contain:
- `gateway.host: "0.0.0.0"` — triggers CFG-001
- API keys in non-`.env` config files — triggers CFG-002
- `tls: false` — triggers CFG-004
- Webhooks without `secret`/`auth`/`token`/`hmac` — triggers CFG-007
- `sandbox: false` — triggers CFG-008
- `password: "admin"` — triggers CFG-009
- No `rateLimit` key — triggers CFG-010
- `auth.bypass: true`, `auth.mode: "none"` — triggers CFG-012
- `dm.policy: "open"` — triggers CFG-013
- `tools.policy: "allow_all"` — triggers CFG-014
- `mdns: true` — triggers CFG-015
- Skill code with `readFileSync()` piped to `fetch()` — triggers SKL-001
- High-entropy hex strings (>5.5 bits/char, >=40 chars) — triggers SKL-002
- `eval()`, `exec()` calls — triggers SKL-003
- `bash -i >& /dev/tcp/...` patterns — triggers SKL-005
- "ignore all previous instructions" in SKILL.md — triggers SKL-007
- Known C2 IP `185.199.228.220` in code — triggers IOC-001
- Known domain `clawhavoc.io` in code — triggers IOC-002
- Skill directory named `filesystm` (distance 1 from `filesystem`) — triggers IOC-005

**Secure fixtures** contain:
- `gateway.host: "127.0.0.1"`, `tls: true`, proper auth, restricted policies
- Benign skill code with no dangerous patterns
- No API keys in config files
- Rate limiting configured, sandbox enabled

### Scenario Switching

All agent Dockerfiles accept a `SCENARIO` build arg:

```dockerfile
ARG SCENARIO=insecure
COPY testing/fixtures/openclaw/${SCENARIO}/ /root/.openclaw/
```

This allows the same Dockerfile to create insecure or secure containers:

```typescript
// Insecure
runVasoScan({ dockerfile: '...', buildArgs: { SCENARIO: 'insecure' } });

// Secure
runVasoScan({ dockerfile: '...', buildArgs: { SCENARIO: 'secure' } });
```

### Timeouts

Integration tests use extended timeouts configured in `testing/vitest.config.integration.ts`:

| Setting | Value | Reason |
|---------|-------|--------|
| `testTimeout` | 120s | Container startup + VASO scan execution |
| `hookTimeout` | 180s | Docker image builds in `beforeAll` |

### Adding a New Agent's Integration Tests

1. Create fixtures under `testing/fixtures/<agent>/insecure/` and `testing/fixtures/<agent>/secure/`
2. Create a Dockerfile at `testing/docker/agents/<agent>.Dockerfile`
3. Create a test file at `testing/integration/<agent>.integration.test.ts`
4. Add the agent to `testing/docker/agents/multi.Dockerfile`
5. Add services to `testing/docker-compose.yml`

## Manual Testing with Docker Compose

For debugging or quick manual checks without running the full vitest suite:

```bash
# Build the base image first
docker compose -f testing/docker-compose.yml build base

# Run a specific scenario
docker compose -f testing/docker-compose.yml run openclaw-insecure
docker compose -f testing/docker-compose.yml run openclaw-secure
docker compose -f testing/docker-compose.yml run nanoclaw-insecure
docker compose -f testing/docker-compose.yml run picoclaw-insecure
docker compose -f testing/docker-compose.yml run multi-insecure

# Pipe output through jq for readability
docker compose -f testing/docker-compose.yml run openclaw-insecure | jq .

# Check specific fields
docker compose -f testing/docker-compose.yml run openclaw-insecure | jq '.totalScore'
docker compose -f testing/docker-compose.yml run openclaw-insecure | jq '.agents[0].results[] | select(.passed == false) | {id, severity, message}'
```

## CI Pipeline

The GitHub Actions workflow (`.github/workflows/integration-tests.yml`) runs integration tests automatically:

```
push/PR to main
  └─> unit-tests job
        └─> integration-tests job (only if unit tests pass)
              ├─ npm ci
              ├─ docker build (base image)
              └─ npm run test:integration
```

The integration job has a 10-minute timeout and runs on `ubuntu-latest` where Docker is pre-installed.

## Troubleshooting

### Docker not running

```
Error: Could not connect to Docker daemon
```

Start Docker Desktop (macOS/Windows) or the Docker service (Linux):

```bash
# Linux
sudo systemctl start docker

# macOS
open -a Docker
```

### Base image build fails

```bash
# Rebuild from scratch
docker rmi vaso-test-base:latest
npm run docker:build-base
```

### Integration test timeout

If tests are timing out, the Docker image build may be slow. Pre-build the base image:

```bash
npm run docker:build-base
```

Subsequent test runs will reuse the cached image.

### No JSON output from container

If tests fail with "No JSON output found", the VASO scan may be crashing inside the container. Debug by running manually:

```bash
docker compose -f testing/docker-compose.yml build openclaw-insecure
docker compose -f testing/docker-compose.yml run openclaw-insecure
```

Check the output for error messages before the JSON.

### Stale Docker images

If fixtures have changed but tests show old results, rebuild:

```bash
docker compose -f testing/docker-compose.yml build --no-cache
```
