# VASO Development Guide

Technical reference for extending VASO with new security checks, agent adapters, output reporters, and analyzers.

## Architecture Overview

```
src/
  cli.ts                    Entry point — registers adapters, checks, wires commands
  core/
    types.ts                All shared interfaces
    engine.ts               ScanEngine — orchestrates detection + checks + scoring
    check-registry.ts       CheckRegistry — stores and queries check modules
    config-loader.ts        Parses JSON, YAML, .env files into ParsedConfig
    scoring.ts              Score computation and grading
    baseline.ts             Differential scanning (save/load/diff)
    patterns.ts             Shared credential detection regex patterns
  adapters/
    adapter.ts              AgentAdapter interface
    registry.ts             AdapterRegistry — parallel agent detection
    openclaw.ts             OpenClaw adapter
    nanoclaw.ts             NanoClaw adapter
    picoclaw.ts             PicoClaw adapter
  checks/
    index.ts                registerAllChecks() — wires all categories
    config/                 15 configuration checks (CFG-*)
    skills/                 10 skill code analysis checks (SKL-*)
    ioc/                    6 IOC matching checks (IOC-*)
    network/                4 network checks (NET-*)
    runtime/                4 runtime checks (RUN-*)
    mcp/                    10 MCP server security checks (MCP-*)
  analyzers/
    ast-analyzer.ts         Babel-based AST analysis with data flow tracing
    pattern-engine.ts       Regex pattern matching engine (40+ rules)
    entropy.ts              Shannon entropy for obfuscation detection
  mcp/
    types.ts                MCP-specific interfaces (MCPServerEntry, MCPConfig, etc.)
    discovery.ts            MCPDiscovery — auto-discovers MCP configs across tools
    source-resolver.ts      Resolves MCP server source code for static analysis
  ioc/
    database.ts             Bundled threat intelligence data
    typosquat.ts            Levenshtein distance for typosquatting
  remediation/
    engine.ts               RemediationEngine — backup + fix orchestration
  reporting/
    reporter.ts             Reporter interface
    index.ts                Reporter factory + registration
    terminal.ts             Chalk-based terminal output
    json.ts                 JSON output
    sarif.ts                SARIF v2.1.0 output
    markdown.ts             Markdown tables output
  commands/
    scan.ts                 vaso scan handler
    detect.ts               vaso detect handler
    fix.ts                  vaso fix handler
    update.ts               vaso update handler
    mcp.ts                  vaso mcp scan/list handler
```

## Scan Engine Flow

### Agent Scan (`vaso scan`)

```
1. cli.ts registers adapters and checks at startup
2. ScanEngine.scan() calls AdapterRegistry.detectAll()
   — each adapter probes the filesystem in parallel (Promise.allSettled)
   — returns AgentInstallation[] for detected frameworks
3. For each installation, engine builds a ScanContext
4. CheckRegistry.getApplicable(agent, platform) filters relevant checks
5. All applicable checks run concurrently (Promise.allSettled)
6. Results are scored (computeScore), graded (scoreToGrade), summarized
7. Reporter renders the ScanResult into the requested format
```

### MCP Scan (`vaso mcp scan`)

```
1. MCPDiscovery.discover() probes known config locations for MCP configs
   — Claude Desktop, Claude Code, Cursor, Windsurf, VS Code, project-level
2. resolveServerSources() resolves local paths to server source code
3. ScanEngine.scanMCP() builds a ScanContext with mcpConfigs + mcpServerSources
4. MCP checks (MCP-001 to MCP-010) run against the context
5. Results are scored, graded, and rendered as with agent scans
```

## Core Interfaces

All interfaces are defined in `src/core/types.ts`.

### CheckModule

Every security check implements this interface:

```typescript
interface CheckModule {
  id: string;                              // e.g. 'CFG-001', 'SKL-003'
  name: string;                            // Human-readable name
  category: CheckCategory;                 // 'config' | 'skills' | 'ioc' | 'network' | 'runtime' | 'policy' | 'mcp'
  severity: Severity;                      // 'critical' | 'warning' | 'info'
  description: string;                     // What this check does

  supportedAgents?: AgentType[];           // Omit = all agents
  supportedPlatforms?: NodeJS.Platform[];  // Omit = all platforms

  run(context: ScanContext): Promise<CheckResult>;
  fix?(context: ScanContext): Promise<FixResult>;  // Optional auto-fix
}
```

### ScanContext

Passed to every check's `run()` method:

```typescript
interface ScanContext {
  installation: AgentInstallation;  // Detected agent info
  configs: ParsedConfig[];          // All parsed config files
  platform: NodeJS.Platform;        // 'darwin' | 'linux' | 'win32'
  skillFiles?: string[];            // Pre-resolved skill file paths
  mcpConfigs?: MCPConfig[];         // Discovered MCP server configs
  mcpServerSources?: MCPServerSource[];  // Resolved MCP server source code
}
```

### CheckResult

Returned by every check:

```typescript
interface CheckResult {
  id: string;
  name: string;
  category: CheckCategory;
  severity: Severity;
  passed: boolean;               // true = no issue found
  message: string;               // Human-readable finding or pass message
  evidence?: Evidence[];          // File locations and code snippets
  fixable?: boolean;             // true if auto-fix is available
  fixDescription?: string;       // What the fix does
}
```

### Evidence

Points to the exact location of a finding:

```typescript
interface Evidence {
  file: string;       // Absolute file path
  line?: number;       // 1-based line number
  snippet?: string;    // Relevant code/config line
  detail?: string;     // Additional context
}
```

### AgentAdapter

Each agent framework implements this interface:

```typescript
interface AgentAdapter {
  readonly agent: AgentType;        // 'openclaw' | 'nanoclaw' | 'picoclaw' | 'mcp'
  readonly displayName: string;     // 'OpenClaw', 'NanoClaw', 'PicoClaw'

  detect(): Promise<AgentInstallation | null>;
  getConfigPaths(): string[];
  getSkillsDir(installDir: string): string | undefined;
  getGatewayInfo(config: Record<string, unknown>): GatewayInfo | undefined;
  getMemoryFiles?(installDir: string): string[];
  getCredentialPaths?(installDir: string): string[];
  getCLICommand?(): string;
}
```

### Reporter

Output format renderers implement this:

```typescript
interface Reporter {
  readonly format: string;
  render(result: ScanResult): string;
}
```

---

## Adding a New Check

### 1. Choose an ID and Category

IDs follow the pattern `<PREFIX>-<NNN>`:

| Category | Prefix | Next available |
|----------|--------|----------------|
| config | CFG | CFG-016 |
| skills | SKL | SKL-011 |
| ioc | IOC | IOC-007 |
| network | NET | NET-005 |
| runtime | RUN | RUN-005 |
| mcp | MCP | MCP-011 |
| policy | POL | POL-001 |

### 2. Create the Check File

Create `src/checks/<category>/<id>.ts`. Example for a new config check:

```typescript
// src/checks/config/cfg-016-example.ts
import type { CheckModule, ScanContext, CheckResult } from '../../core/types.js';

export const cfg016: CheckModule = {
  id: 'CFG-016',
  name: 'Insecure Log Level',
  category: 'config',
  severity: 'warning',
  description: 'Check if debug logging is enabled in production, which may leak sensitive data',

  // Optional: restrict to specific agents or platforms
  // supportedAgents: ['openclaw'],
  // supportedPlatforms: ['linux', 'darwin'],

  async run(ctx: ScanContext): Promise<CheckResult> {
    const evidence = [];

    for (const config of ctx.configs) {
      const logLevel = config.data.logLevel ?? config.data.LOG_LEVEL;

      if (logLevel === 'debug' || logLevel === 'trace') {
        evidence.push({
          file: config.filePath,
          detail: `Log level set to "${logLevel}" — may expose sensitive data`,
        });
      }
    }

    return {
      id: 'CFG-016',
      name: 'Insecure Log Level',
      category: 'config',
      severity: 'warning',
      passed: evidence.length === 0,
      message: evidence.length === 0
        ? 'Log level is not set to debug/trace'
        : 'Debug logging enabled — may leak sensitive data in logs',
      evidence: evidence.length > 0 ? evidence : undefined,
    };
  },
};
```

### 3. Register the Check

Add the export to the category index file. For config checks, edit `src/checks/config/index.ts`:

```typescript
import { cfg016 } from './cfg-016-example.js';

export const configChecks: CheckModule[] = [
  // ... existing checks
  cfg016,
];
```

All category index files are imported by `src/checks/index.ts`, which calls `registerAllChecks()` at startup. No changes needed there unless you add a new category.

### 4. Add a Fixable Check (Optional)

Add a `fix()` method and mark the result as `fixable: true`:

```typescript
export const cfg016: CheckModule = {
  // ... id, name, category, severity, description

  async run(ctx: ScanContext): Promise<CheckResult> {
    // ... detection logic
    return {
      // ...
      fixable: true,
      fixDescription: 'Set log level to "warn"',
    };
  },

  async fix(ctx: ScanContext): Promise<FixResult> {
    // Modify the config file
    for (const config of ctx.configs) {
      if (config.data.logLevel === 'debug' || config.data.logLevel === 'trace') {
        config.data.logLevel = 'warn';
        const { writeFile } = await import('node:fs/promises');
        await writeFile(config.filePath, JSON.stringify(config.data, null, 2));
        return { checkId: 'CFG-016', applied: true, message: 'Log level set to warn' };
      }
    }
    return { checkId: 'CFG-016', applied: false, message: 'No config to fix' };
  },
};
```

The `RemediationEngine` handles backups automatically before calling `fix()`.

### 5. Write Tests

Create or extend a test file. Config checks share `src/checks/config/config-checks.test.ts`. For a new category, create a new test file:

```typescript
import { describe, it, expect } from 'vitest';
import { cfg016 } from './cfg-016-example.js';
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

describe('CFG-016 Insecure Log Level', () => {
  it('fails when log level is debug', async () => {
    const ctx = makeContext({ logLevel: 'debug' });
    const result = await cfg016.run(ctx);
    expect(result.passed).toBe(false);
    expect(result.severity).toBe('warning');
  });

  it('passes when log level is warn', async () => {
    const ctx = makeContext({ logLevel: 'warn' });
    const result = await cfg016.run(ctx);
    expect(result.passed).toBe(true);
  });

  it('passes when log level is not set', async () => {
    const ctx = makeContext({});
    const result = await cfg016.run(ctx);
    expect(result.passed).toBe(true);
  });
});
```

Run tests:

```bash
# All tests
npm test

# Single file
npx vitest run src/checks/config/config-checks.test.ts
```

### Skill Check Pattern

Skill checks scan source code files. Use the shared `getSkillFiles()` helper and choose between the AST analyzer or pattern engine:

```typescript
import { analyzeCode } from '../../analyzers/ast-analyzer.js';
import { scanWithPatterns } from '../../analyzers/pattern-engine.js';

// AST-based (data flow, eval/exec, network calls):
const flows = analyzeCode(code, filePath);
const exfilFlows = flows.filter(f => f.type === 'source-to-sink');

// Pattern-based (regex matching):
const matches = scanWithPatterns(code, filePath, ['reverse-shell', 'curl-pipe']);
```

### IOC Check Pattern

IOC checks compare against the bundled threat database:

```typescript
import { getIOCDatabase } from '../../ioc/database.js';

const db = getIOCDatabase();
// db.c2Ips, db.maliciousDomains, db.fileHashes, db.maliciousPublishers, etc.
```

### MCP Check Pattern

MCP checks operate on discovered MCP server configurations and optionally their resolved source code. Use `ctx.mcpConfigs` for config-level checks and `ctx.mcpServerSources` for source code analysis:

```typescript
// Config-level check (e.g. transport security, credential exposure):
for (const config of ctx.mcpConfigs ?? []) {
  for (const server of config.servers) {
    if (server.transport === 'sse' && server.url && !server.url.startsWith('https://')) {
      evidence.push({
        file: config.filePath,
        detail: `Server "${server.name}" uses insecure SSE transport`,
      });
    }
  }
}

// Source-level check (e.g. tool injection, data exfiltration):
for (const source of ctx.mcpServerSources ?? []) {
  if (!source.sourceCode) continue;
  const flows = analyzeCode(source.sourceCode, source.localPath ?? source.serverName);
  // ... analyze data flows
}
```

Use `src/core/patterns.ts` for shared credential detection regexes (OpenAI, Anthropic, AWS, GitHub, GitLab, Slack keys, and private keys).

---

## Adding a New Agent Adapter

### 1. Extend AgentType

Add the new agent type to `src/core/types.ts`:

```typescript
export type AgentType = 'openclaw' | 'nanoclaw' | 'picoclaw' | 'mcp' | 'megaclaw';
```

### 2. Create the Adapter

Create `src/adapters/megaclaw.ts`:

```typescript
import { access } from 'node:fs/promises';
import { join } from 'node:path';
import { homedir } from 'node:os';
import type { AgentAdapter } from './adapter.js';
import type { AgentInstallation, GatewayInfo } from '../core/types.js';
import { loadConfig } from '../core/config-loader.js';

async function dirExists(path: string): Promise<boolean> {
  try { await access(path); return true; } catch { return false; }
}

export const megaclawAdapter: AgentAdapter = {
  agent: 'megaclaw',
  displayName: 'MegaClaw',

  async detect(): Promise<AgentInstallation | null> {
    const installDir = join(homedir(), '.megaclaw');
    if (!(await dirExists(installDir))) return null;

    const configFiles = [];
    for (const filename of ['config.json', 'settings.yaml', '.env']) {
      try {
        configFiles.push(await loadConfig(join(installDir, filename)));
      } catch {}
    }

    if (configFiles.length === 0) return null;

    const merged: Record<string, unknown> = {};
    for (const c of configFiles) Object.assign(merged, c.data);

    return {
      agent: 'megaclaw',
      installDir,
      configFiles,
      skillsDir: this.getSkillsDir(installDir),
      gateway: this.getGatewayInfo(merged),
    };
  },

  getConfigPaths(): string[] {
    const dir = join(homedir(), '.megaclaw');
    return ['config.json', 'settings.yaml', '.env'].map(f => join(dir, f));
  },

  getSkillsDir(installDir: string): string | undefined {
    return join(installDir, 'skills');
  },

  getGatewayInfo(config: Record<string, unknown>): GatewayInfo | undefined {
    const gw = config.gateway as Record<string, unknown> | undefined;
    if (!gw) return undefined;
    return {
      host: gw.host as string | undefined,
      port: gw.port as number | undefined,
      authMode: gw.authMode as string | undefined,
      tls: gw.tls as boolean | undefined,
    };
  },

  getCredentialPaths(installDir: string): string[] {
    return [join(installDir, '.env'), join(installDir, 'auth.json')];
  },

  getCLICommand(): string {
    return 'megaclaw';
  },
};
```

### 3. Register the Adapter

In `src/cli.ts`:

```typescript
import { megaclawAdapter } from './adapters/megaclaw.js';

adapterRegistry.register(megaclawAdapter);
```

### 4. Agent-Specific Checks

If the new agent has unique security concerns, create checks with `supportedAgents` set:

```typescript
export const cfg017: CheckModule = {
  id: 'CFG-017',
  name: 'MegaClaw Debug Mode',
  category: 'config',
  severity: 'critical',
  description: 'Check if MegaClaw debug mode is enabled',
  supportedAgents: ['megaclaw'],  // Only runs for MegaClaw

  async run(ctx: ScanContext): Promise<CheckResult> {
    // ... detection logic
  },
};
```

Checks without `supportedAgents` run for all agents automatically.

---

## Adding a New Output Reporter

### 1. Create the Reporter

Create `src/reporting/html.ts`:

```typescript
import type { ScanResult } from '../core/types.js';
import type { Reporter } from './reporter.js';

export class HtmlReporter implements Reporter {
  readonly format = 'html';

  render(result: ScanResult): string {
    const findings = result.agents.flatMap(a =>
      a.results.filter(r => !r.passed)
    );

    return `<!DOCTYPE html>
<html>
<head><title>VASO Report</title></head>
<body>
  <h1>VASO Security Scan</h1>
  <p>Score: ${result.totalScore}/100 (${result.totalGrade})</p>
  <p>Critical: ${result.summary.critical} | Warning: ${result.summary.warning} | Info: ${result.summary.info}</p>
  <table>
    <tr><th>ID</th><th>Name</th><th>Severity</th><th>Message</th></tr>
    ${findings.map(f => `<tr><td>${f.id}</td><td>${f.name}</td><td>${f.severity}</td><td>${f.message}</td></tr>`).join('\n')}
  </table>
</body>
</html>`;
  }
}
```

### 2. Register the Reporter

In `src/reporting/index.ts`:

```typescript
import { HtmlReporter } from './html.js';

const reporters: Record<string, () => Reporter> = {
  terminal: () => new TerminalReporter(),
  json: () => new JsonReporter(),
  sarif: () => new SarifReporter(),
  markdown: () => new MarkdownReporter(),
  html: () => new HtmlReporter(),
};
```

You can also register reporters dynamically:

```typescript
import { registerReporter } from './reporting/index.js';

registerReporter('html', () => new HtmlReporter());
```

### 3. Wire the CLI Option

In `src/cli.ts`, the `--format` option already accepts any string. Add validation if desired:

```typescript
.option('-f, --format <format>', 'output format (terminal, json, sarif, markdown, html)', 'terminal')
```

---

## Adding a New Check Category

### 1. Create the Category Directory

```bash
mkdir src/checks/policy
```

### 2. Create Checks

Create individual check files (`pol-001-*.ts`, etc.) following the patterns above.

### 3. Create the Index

```typescript
// src/checks/policy/index.ts
import type { CheckModule } from '../../core/types.js';
import { pol001 } from './pol-001-example.js';

export const policyChecks: CheckModule[] = [pol001];
```

### 4. Register in the Master Index

Edit `src/checks/index.ts`:

```typescript
import { policyChecks } from './policy/index.js';

export function registerAllChecks(): void {
  checkRegistry.registerAll(configChecks);
  checkRegistry.registerAll(skillChecks);
  checkRegistry.registerAll(iocChecks);
  checkRegistry.registerAll(networkChecks);
  checkRegistry.registerAll(runtimeChecks);
  checkRegistry.registerAll(mcpChecks);
  checkRegistry.registerAll(policyChecks);  // Add this
}
```

---

## Working with the Analyzers

### AST Analyzer

`src/analyzers/ast-analyzer.ts` parses JavaScript/TypeScript with `@babel/parser` and walks the AST with `@babel/traverse`.

```typescript
import { analyzeCode } from '../analyzers/ast-analyzer.js';

const flows = analyzeCode(sourceCode, filePath);
```

Returns an array of `DataFlow` objects:

```typescript
interface DataFlow {
  type: 'source-to-sink' | 'eval-exec' | 'suspicious-network' | 'sensitive-path';
  source?: string;
  sink?: string;
  line: number;
  snippet: string;
  description: string;
}
```

Tracked sources: `readFile`, `readFileSync`, `createReadStream`, `readdir`, `readdirSync`, `process.env`.

Tracked sinks: `fetch`, `http.request`, `https.request`, `net.connect`, `WebSocket`, `XMLHttpRequest`.

### Pattern Engine

`src/analyzers/pattern-engine.ts` runs regex rules against source code line-by-line.

```typescript
import { scanWithPatterns } from '../analyzers/pattern-engine.js';

// Scan with specific categories
const matches = scanWithPatterns(code, filePath, ['reverse-shell', 'credential-harvest']);

// Scan with all categories (omit filter)
const allMatches = scanWithPatterns(code, filePath);
```

Available categories: `reverse-shell`, `curl-pipe`, `credential-harvest`, `exfiltration`, `prompt-injection`, `crypto-wallet`, `obfuscation`, `code-exec`.

Returns an array of `PatternMatch`:

```typescript
interface PatternMatch {
  rule: string;       // Rule identifier
  category: string;   // Category name
  severity: Severity;
  line: number;
  snippet: string;
  description: string;
}
```

To add patterns, append to the `PATTERNS` array in `pattern-engine.ts`:

```typescript
{ id: 'custom-001', category: 'exfiltration', severity: 'critical',
  pattern: /ngrok\.io|serveo\.net/i,
  description: 'Tunneling service domain detected' },
```

### Entropy Analyzer

`src/analyzers/entropy.ts` calculates Shannon entropy to detect obfuscated or packed code.

```typescript
import { shannonEntropy, findHighEntropyBlocks } from '../analyzers/entropy.js';

// Single string
const entropy = shannonEntropy('some string');

// Find high-entropy blocks in source code (threshold: 5.5 bits/char, min length: 40)
const blocks = findHighEntropyBlocks(code);
// Returns: { content: string, entropy: number, line: number }[]
```

---

## IOC Database

The bundled IOC database is in `src/ioc/database.ts`. To add new indicators:

```typescript
// In database.ts, add to the appropriate array:
const C2_IPS: string[] = [
  // ... existing IPs
  '203.0.113.99',  // New C2 IP from threat report
];

const MALICIOUS_DOMAINS: string[] = [
  // ... existing domains
  'evil-skills.example.com',
];
```

The `vaso update` command calls `reloadIOCDatabase()` which currently reloads from the bundled data. Future versions will support external IOC feeds.

### Typosquatting Detection

Add trusted skill names to `src/ioc/typosquat.ts`:

```typescript
const TRUSTED_SKILLS: string[] = [
  // ... existing names
  'new-trusted-skill',
];
```

Skills with a Levenshtein distance <= 2 from any trusted name are flagged.

---

## Scoring System

Defined in `src/core/scoring.ts`:

- Base score: 100
- Each failed **critical** check: -12 points
- Each failed **warning** check: -5 points
- **Info** findings: no score impact
- Score is clamped to 0-100

Grades: A (90+), B (80+), C (70+), D (60+), F (<60).

When multiple agents are scanned, the total score is the average of per-agent scores.

---

## Config Loader

`src/core/config-loader.ts` auto-detects file format by extension:

| Extension | Parser |
|-----------|--------|
| `.json` | `JSON.parse` |
| `.yaml`, `.yml` | `yaml` npm package |
| `.env` | Custom parser (handles quotes, comments, multiline) |

Returns a `ParsedConfig` with both the raw string content and the parsed `data` object. Checks can use either for detection (structured lookup via `data`, or regex via `raw`).

---

## Build and Test

```bash
npm run build          # tsup: src/cli.ts → dist/cli.js (single ESM bundle)
npm test               # vitest: run all tests
npx vitest run <path>  # Run a single test file
npm run lint           # tsc --noEmit (type checking only)
npm run dev            # tsup --watch (rebuild on change)
```

The build produces a single `dist/cli.js` file (~120 KB) with all dependencies bundled except Node.js built-ins.

---

## Conventions

- **Check IDs** are uppercase: `CFG-001`, `SKL-003`, `IOC-005`, `MCP-001`
- **File names** are lowercase with the ID: `cfg-001-gateway-binding.ts`, `mcp-001-config-discovery.ts`
- **Exports** use camelCase matching the ID: `cfg001`, `skl003`, `ioc005`, `mcp001`
- **Category indexes** export a `<category>Checks` array: `configChecks`, `skillChecks`, `mcpChecks`
- **Tests** go in `.test.ts` files alongside the source or in a shared `<category>.test.ts`
- Checks without `supportedAgents` apply to all agents
- Checks without `supportedPlatforms` apply to all platforms
- All analysis is read-only; only `fix()` methods modify the filesystem
- `fix()` must return a `FixResult` indicating whether the fix was applied
