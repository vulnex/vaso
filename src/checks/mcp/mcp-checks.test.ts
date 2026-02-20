import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { ScanContext, AgentInstallation } from '../../core/types.js';
import type { MCPConfig, MCPServerSource } from '../../mcp/types.js';
import { mcp001 } from './mcp-001-config-discovery.js';
import { mcp002 } from './mcp-002-transport-security.js';
import { mcp003 } from './mcp-003-credential-exposure.js';
import { mcp004 } from './mcp-004-overprivileged-tools.js';
import { mcp005 } from './mcp-005-tool-injection.js';
import { mcp006 } from './mcp-006-data-exfiltration.js';
import { mcp007 } from './mcp-007-prompt-injection.js';
import { mcp008 } from './mcp-008-server-provenance.js';
import { mcp009 } from './mcp-009-permission-scope.js';
import { mcp010 } from './mcp-010-rug-pull-risk.js';

const FIXTURES = join(__dirname, '../../../testing/fixtures/mcp');

const vulnerableSource = readFileSync(
  join(FIXTURES, 'mcp-server-source/vulnerable-server/index.js'),
  'utf-8',
);
const safeSource = readFileSync(
  join(FIXTURES, 'mcp-server-source/safe-server/index.js'),
  'utf-8',
);

const baseInstallation: AgentInstallation = {
  agent: 'mcp',
  installDir: '/tmp/test-mcp',
  configFiles: [],
};

function makeContext(overrides: {
  mcpConfigs?: MCPConfig[];
  mcpServerSources?: MCPServerSource[];
} = {}): ScanContext {
  return {
    installation: baseInstallation,
    configs: [],
    platform: 'darwin',
    ...overrides,
  };
}

// --- Insecure config fixtures ---
const insecureConfigs: MCPConfig[] = [
  {
    source: 'Claude Desktop',
    filePath: join(FIXTURES, 'insecure/claude_desktop_config.json'),
    servers: [
      {
        name: 'risky-server',
        command: 'npx',
        args: ['-y', 'mcp-server-risky'],
        env: {
          OPENAI_API_KEY: 'sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx',
          AWS_SECRET_ACCESS_KEY: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
          DATABASE_PASSWORD: 'super_secret_password_12345',
        },
        transport: 'stdio',
      },
      {
        name: 'insecure-sse',
        url: 'http://0.0.0.0:8080/sse',
        transport: 'sse',
      },
      {
        name: 'admin-server',
        command: 'node',
        args: ['/opt/mcp/admin-server.js', '--host', '0.0.0.0'],
        env: {
          GITHUB_TOKEN: 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij',
        },
        transport: 'stdio',
      },
      {
        name: 'typo-filesystam',
        command: 'npx',
        args: ['@modelcontextprotocol/server-filesystam'],
        transport: 'stdio',
      },
    ],
  },
];

const secureConfigs: MCPConfig[] = [
  {
    source: 'Claude Desktop',
    filePath: join(FIXTURES, 'secure/claude_desktop_config.json'),
    servers: [
      {
        name: 'filesystem',
        command: 'npx',
        args: ['-y', '@modelcontextprotocol/server-filesystem@1.2.0', '/Users/me/projects'],
        transport: 'stdio',
      },
      {
        name: 'github',
        command: 'npx',
        args: ['-y', '@modelcontextprotocol/server-github@0.5.1'],
        env: { GITHUB_TOKEN: '${GITHUB_TOKEN}' },
        transport: 'stdio',
      },
      {
        name: 'secure-sse',
        url: 'https://mcp.example.com/sse',
        transport: 'sse',
      },
    ],
  },
];

const vulnerableSources: MCPServerSource[] = [
  {
    serverName: 'risky-server',
    localPath: join(FIXTURES, 'mcp-server-source/vulnerable-server/index.js'),
    sourceCode: vulnerableSource,
  },
];

const safeSources: MCPServerSource[] = [
  {
    serverName: 'safe-server',
    localPath: join(FIXTURES, 'mcp-server-source/safe-server/index.js'),
    sourceCode: safeSource,
  },
];

// ==================== MCP-001: Config Discovery ====================
describe('MCP-001: Config Discovery', () => {
  it('reports info for found servers', async () => {
    const ctx = makeContext({ mcpConfigs: insecureConfigs });
    const result = await mcp001.run(ctx);

    console.log(`[MCP-001] insecure → passed: ${result.passed}, evidence: ${result.evidence?.length ?? 0}`);

    expect(result.passed).toBe(true); // info check, always passes
    expect(result.severity).toBe('info');
    expect(result.evidence?.length).toBe(4);
    expect(result.message).toContain('4 MCP server(s)');
  });

  it('reports empty when no configs', async () => {
    const ctx = makeContext({ mcpConfigs: [] });
    const result = await mcp001.run(ctx);

    console.log(`[MCP-001] empty → message: ${result.message}`);

    expect(result.passed).toBe(true);
    expect(result.message).toContain('No MCP servers');
  });
});

// ==================== MCP-002: Transport Security ====================
describe('MCP-002: Transport Security', () => {
  it('fails for HTTP on 0.0.0.0', async () => {
    const ctx = makeContext({ mcpConfigs: insecureConfigs });
    const result = await mcp002.run(ctx);

    console.log(`[MCP-002] insecure → passed: ${result.passed}, evidence: ${result.evidence?.length ?? 0}`);

    expect(result.passed).toBe(false);
    expect(result.severity).toBe('critical');
    // insecure-sse has http:// on 0.0.0.0 (2 findings) + admin-server has 0.0.0.0 in args
    expect(result.evidence!.length).toBeGreaterThanOrEqual(2);
  });

  it('passes for HTTPS transport', async () => {
    const ctx = makeContext({ mcpConfigs: secureConfigs });
    const result = await mcp002.run(ctx);

    console.log(`[MCP-002] secure → passed: ${result.passed}`);

    expect(result.passed).toBe(true);
  });
});

// ==================== MCP-003: Credential Exposure ====================
describe('MCP-003: Credential Exposure', () => {
  it('detects plaintext API keys in env blocks', async () => {
    const ctx = makeContext({ mcpConfigs: insecureConfigs });
    const result = await mcp003.run(ctx);

    console.log(`[MCP-003] insecure → passed: ${result.passed}, evidence: ${result.evidence?.length ?? 0}`);
    for (const e of result.evidence ?? []) {
      console.log(`  ${e.detail}`);
    }

    expect(result.passed).toBe(false);
    expect(result.severity).toBe('critical');
    // Should find OpenAI key, GitHub PAT at minimum
    expect(result.evidence!.length).toBeGreaterThanOrEqual(2);
  });

  it('passes for env references (not plaintext)', async () => {
    const ctx = makeContext({ mcpConfigs: secureConfigs });
    const result = await mcp003.run(ctx);

    console.log(`[MCP-003] secure → passed: ${result.passed}`);

    expect(result.passed).toBe(true);
  });
});

// ==================== MCP-004: Overprivileged Tools ====================
describe('MCP-004: Overprivileged Tools', () => {
  it('detects exec and sensitive file access in vulnerable source', async () => {
    const ctx = makeContext({ mcpServerSources: vulnerableSources });
    const result = await mcp004.run(ctx);

    console.log(`[MCP-004] vulnerable → passed: ${result.passed}, evidence: ${result.evidence?.length ?? 0}`);
    for (const e of result.evidence ?? []) {
      console.log(`  line ${e.line}: ${e.detail}`);
    }

    expect(result.passed).toBe(false);
    expect(result.severity).toBe('critical');
    expect(result.evidence!.length).toBeGreaterThanOrEqual(2);
  });

  it('passes for safe server source', async () => {
    const ctx = makeContext({ mcpServerSources: safeSources });
    const result = await mcp004.run(ctx);

    console.log(`[MCP-004] safe → passed: ${result.passed}, evidence: ${result.evidence?.length ?? 0}`);

    expect(result.passed).toBe(true);
  });
});

// ==================== MCP-005: Tool Input Injection ====================
describe('MCP-005: Tool Input Injection', () => {
  it('detects unsanitized input patterns in vulnerable source', async () => {
    const ctx = makeContext({ mcpServerSources: vulnerableSources });
    const result = await mcp005.run(ctx);

    console.log(`[MCP-005] vulnerable → passed: ${result.passed}, evidence: ${result.evidence?.length ?? 0}`);
    for (const e of result.evidence ?? []) {
      console.log(`  line ${e.line}: ${e.detail}`);
    }

    expect(result.passed).toBe(false);
    expect(result.severity).toBe('critical');
    expect(result.evidence!.length).toBeGreaterThanOrEqual(1);
  });

  it('passes for safe server source', async () => {
    const ctx = makeContext({ mcpServerSources: safeSources });
    const result = await mcp005.run(ctx);

    console.log(`[MCP-005] safe → passed: ${result.passed}`);

    expect(result.passed).toBe(true);
  });
});

// ==================== MCP-006: Data Exfiltration ====================
describe('MCP-006: Data Exfiltration Risk', () => {
  it('detects source-to-sink data flow in vulnerable source', async () => {
    const ctx = makeContext({ mcpServerSources: vulnerableSources });
    const result = await mcp006.run(ctx);

    console.log(`[MCP-006] vulnerable → passed: ${result.passed}, evidence: ${result.evidence?.length ?? 0}`);
    for (const e of result.evidence ?? []) {
      console.log(`  line ${e.line}: ${e.detail}`);
    }

    expect(result.passed).toBe(false);
    expect(result.severity).toBe('critical');
    expect(result.evidence!.length).toBeGreaterThanOrEqual(1);
  });

  it('passes for safe server source', async () => {
    const ctx = makeContext({ mcpServerSources: safeSources });
    const result = await mcp006.run(ctx);

    console.log(`[MCP-006] safe → passed: ${result.passed}`);

    expect(result.passed).toBe(true);
  });
});

// ==================== MCP-007: Prompt Injection ====================
describe('MCP-007: Prompt Injection via Tool Results', () => {
  it('detects raw external content in tool results', async () => {
    const ctx = makeContext({ mcpServerSources: vulnerableSources });
    const result = await mcp007.run(ctx);

    console.log(`[MCP-007] vulnerable → passed: ${result.passed}, evidence: ${result.evidence?.length ?? 0}`);
    for (const e of result.evidence ?? []) {
      console.log(`  line ${e.line}: ${e.detail}`);
    }

    expect(result.passed).toBe(false);
    expect(result.severity).toBe('warning');
    expect(result.evidence!.length).toBeGreaterThanOrEqual(1);
  });

  it('passes for safe server source', async () => {
    const ctx = makeContext({ mcpServerSources: safeSources });
    const result = await mcp007.run(ctx);

    console.log(`[MCP-007] safe → passed: ${result.passed}`);

    expect(result.passed).toBe(true);
  });
});

// ==================== MCP-008: Server Provenance ====================
describe('MCP-008: Server Provenance', () => {
  it('detects typosquatting package names', async () => {
    const sources: MCPServerSource[] = [
      {
        serverName: 'typo-filesystam',
        packageName: '@modelcontextprotocol/server-filesystam',
      },
    ];

    const ctx = makeContext({ mcpConfigs: insecureConfigs, mcpServerSources: sources });
    const result = await mcp008.run(ctx);

    console.log(`[MCP-008] typosquat → passed: ${result.passed}, evidence: ${result.evidence?.length ?? 0}`);
    for (const e of result.evidence ?? []) {
      console.log(`  ${e.detail}`);
    }

    expect(result.passed).toBe(false);
    expect(result.evidence!.some(e => e.detail?.includes('typosquat'))).toBe(true);
  });

  it('passes for known trusted packages', async () => {
    const sources: MCPServerSource[] = [
      {
        serverName: 'filesystem',
        packageName: '@modelcontextprotocol/server-filesystem',
      },
    ];

    const ctx = makeContext({ mcpConfigs: secureConfigs, mcpServerSources: sources });
    const result = await mcp008.run(ctx);

    console.log(`[MCP-008] trusted → passed: ${result.passed}`);

    expect(result.passed).toBe(true);
  });
});

// ==================== MCP-009: Permission Scope ====================
describe('MCP-009: Permission Scope', () => {
  it('detects overprivileged patterns in source code', async () => {
    const ctx = makeContext({ mcpConfigs: insecureConfigs, mcpServerSources: vulnerableSources });
    const result = await mcp009.run(ctx);

    console.log(`[MCP-009] vulnerable → passed: ${result.passed}, evidence: ${result.evidence?.length ?? 0}`);
    for (const e of result.evidence ?? []) {
      console.log(`  ${e.detail}`);
    }

    // admin-server name triggers overprivileged + source has chmod 777
    expect(result.passed).toBe(false);
    expect(result.evidence!.length).toBeGreaterThanOrEqual(1);
  });

  it('passes for well-scoped servers', async () => {
    const ctx = makeContext({ mcpConfigs: secureConfigs, mcpServerSources: safeSources });
    const result = await mcp009.run(ctx);

    console.log(`[MCP-009] safe → passed: ${result.passed}`);

    expect(result.passed).toBe(true);
  });
});

// ==================== MCP-010: Rug Pull Risk ====================
describe('MCP-010: Rug Pull Risk', () => {
  it('detects unpinned npx packages', async () => {
    const ctx = makeContext({ mcpConfigs: insecureConfigs });
    const result = await mcp010.run(ctx);

    console.log(`[MCP-010] unpinned → passed: ${result.passed}, evidence: ${result.evidence?.length ?? 0}`);
    for (const e of result.evidence ?? []) {
      console.log(`  ${e.detail}`);
    }

    expect(result.passed).toBe(false);
    expect(result.severity).toBe('warning');
    // risky-server uses npx -y without version pinning
    expect(result.evidence!.length).toBeGreaterThanOrEqual(1);
  });

  it('passes for version-pinned packages', async () => {
    const ctx = makeContext({ mcpConfigs: secureConfigs });
    const result = await mcp010.run(ctx);

    console.log(`[MCP-010] pinned → passed: ${result.passed}`);

    // secure configs use @1.2.0 and @0.5.1 version pins
    expect(result.passed).toBe(true);
  });
});
