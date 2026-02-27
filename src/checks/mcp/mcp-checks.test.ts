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
import { mcp011 } from './mcp-011-oauth-endpoint-https.js';
import { mcp012 } from './mcp-012-oauth-client-secret-exposure.js';
import { mcp013 } from './mcp-013-missing-pkce.js';
import { mcp014 } from './mcp-014-insecure-token-storage.js';
import { mcp015 } from './mcp-015-token-passthrough.js';
import { mcp016 } from './mcp-016-insecure-redirect-uri.js';
import { mcp017 } from './mcp-017-overly-broad-scopes.js';
import { mcp018 } from './mcp-018-missing-state-parameter.js';
import { mcp019 } from './mcp-019-toxic-tool-flow.js';
import { mcp020 } from './mcp-020-tool-definition-rug-pull.js';
import { saveToolBaseline } from '../../mcp/tool-baseline.js';
import { rm } from 'node:fs/promises';
import { join as pathJoin } from 'node:path';
import { homedir } from 'node:os';

const FIXTURES = join(__dirname, '../../../testing/fixtures/mcp');

const vulnerableSource = readFileSync(
  join(FIXTURES, 'mcp-server-source/vulnerable-server/index.js'),
  'utf-8',
);
const safeSource = readFileSync(
  join(FIXTURES, 'mcp-server-source/safe-server/index.js'),
  'utf-8',
);
const vulnerableOAuthSource = readFileSync(
  join(FIXTURES, 'mcp-server-source/vulnerable-oauth-server/index.js'),
  'utf-8',
);
const safeOAuthSource = readFileSync(
  join(FIXTURES, 'mcp-server-source/safe-oauth-server/index.js'),
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

// --- OAuth-specific config fixtures ---
const insecureOAuthConfigs: MCPConfig[] = [
  {
    source: 'Claude Desktop',
    filePath: join(FIXTURES, 'insecure/claude_desktop_config.json'),
    servers: [
      {
        name: 'oauth-server',
        command: 'node',
        args: ['oauth-server.js'],
        env: {
          OAUTH_TOKEN_ENDPOINT: 'http://auth.example.com/oauth/token',
          AUTH_URL: 'http://auth.example.com/authorize',
          CLIENT_SECRET: 'super-secret-client-value-abc123xyz789',
          REFRESH_TOKEN: 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.fakesig',
          OAUTH_REDIRECT_URI: 'http://myapp.example.com/callback',
          OAUTH_SCOPE: '*',
        },
        transport: 'stdio',
      },
    ],
  },
];

const secureOAuthConfigs: MCPConfig[] = [
  {
    source: 'Claude Desktop',
    filePath: join(FIXTURES, 'secure/claude_desktop_config.json'),
    servers: [
      {
        name: 'oauth-server',
        command: 'node',
        args: ['oauth-server.js'],
        env: {
          OAUTH_TOKEN_ENDPOINT: 'https://auth.example.com/oauth/token',
          AUTH_URL: 'https://auth.example.com/authorize',
          CLIENT_SECRET: '${CLIENT_SECRET}',
          REFRESH_TOKEN: '${REFRESH_TOKEN}',
          OAUTH_REDIRECT_URI: 'https://myapp.example.com/callback',
          OAUTH_SCOPE: 'read:data write:own',
        },
        transport: 'stdio',
      },
    ],
  },
];

const vulnerableOAuthSources: MCPServerSource[] = [
  {
    serverName: 'oauth-server',
    localPath: join(FIXTURES, 'mcp-server-source/vulnerable-oauth-server/index.js'),
    sourceCode: vulnerableOAuthSource,
  },
];

const safeOAuthSources: MCPServerSource[] = [
  {
    serverName: 'oauth-server',
    localPath: join(FIXTURES, 'mcp-server-source/safe-oauth-server/index.js'),
    sourceCode: safeOAuthSource,
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

// ==================== MCP-011: OAuth Endpoint HTTPS ====================
describe('MCP-011: OAuth Endpoint HTTPS', () => {
  it('detects HTTP OAuth endpoints in config and source', async () => {
    const ctx = makeContext({ mcpConfigs: insecureOAuthConfigs, mcpServerSources: vulnerableOAuthSources });
    const result = await mcp011.run(ctx);

    console.log(`[MCP-011] insecure → passed: ${result.passed}, evidence: ${result.evidence?.length ?? 0}`);
    for (const e of result.evidence ?? []) {
      console.log(`  ${e.detail}`);
    }

    expect(result.passed).toBe(false);
    expect(result.severity).toBe('critical');
    expect(result.evidence!.length).toBeGreaterThanOrEqual(2);
  });

  it('passes for HTTPS OAuth endpoints', async () => {
    const ctx = makeContext({ mcpConfigs: secureOAuthConfigs, mcpServerSources: safeOAuthSources });
    const result = await mcp011.run(ctx);

    console.log(`[MCP-011] secure → passed: ${result.passed}`);

    expect(result.passed).toBe(true);
  });

  it('allows HTTP localhost as exception', async () => {
    const localhostConfigs: MCPConfig[] = [
      {
        source: 'Test',
        filePath: '/tmp/test.json',
        servers: [{
          name: 'local-dev',
          command: 'node',
          args: ['server.js'],
          env: { OAUTH_TOKEN_ENDPOINT: 'http://localhost:8080/oauth/token' },
          transport: 'stdio',
        }],
      },
    ];

    const ctx = makeContext({ mcpConfigs: localhostConfigs });
    const result = await mcp011.run(ctx);

    console.log(`[MCP-011] localhost → passed: ${result.passed}`);

    expect(result.passed).toBe(true);
  });
});

// ==================== MCP-012: OAuth Client Secret Exposure ====================
describe('MCP-012: OAuth Client Secret Exposure', () => {
  it('detects plaintext OAuth secrets in env blocks', async () => {
    const ctx = makeContext({ mcpConfigs: insecureOAuthConfigs });
    const result = await mcp012.run(ctx);

    console.log(`[MCP-012] insecure → passed: ${result.passed}, evidence: ${result.evidence?.length ?? 0}`);
    for (const e of result.evidence ?? []) {
      console.log(`  ${e.detail}`);
    }

    expect(result.passed).toBe(false);
    expect(result.severity).toBe('critical');
    // CLIENT_SECRET key + REFRESH_TOKEN key at minimum
    expect(result.evidence!.length).toBeGreaterThanOrEqual(2);
  });

  it('passes for env variable references', async () => {
    const ctx = makeContext({ mcpConfigs: secureOAuthConfigs });
    const result = await mcp012.run(ctx);

    console.log(`[MCP-012] secure → passed: ${result.passed}`);

    expect(result.passed).toBe(true);
  });
});

// ==================== MCP-013: Missing PKCE ====================
describe('MCP-013: Missing PKCE', () => {
  it('detects OAuth flows without PKCE', async () => {
    const ctx = makeContext({ mcpServerSources: vulnerableOAuthSources });
    const result = await mcp013.run(ctx);

    console.log(`[MCP-013] vulnerable → passed: ${result.passed}, evidence: ${result.evidence?.length ?? 0}`);
    for (const e of result.evidence ?? []) {
      console.log(`  line ${e.line}: ${e.detail}`);
    }

    expect(result.passed).toBe(false);
    expect(result.severity).toBe('critical');
    expect(result.evidence!.length).toBeGreaterThanOrEqual(1);
  });

  it('passes for OAuth flows with PKCE S256', async () => {
    const ctx = makeContext({ mcpServerSources: safeOAuthSources });
    const result = await mcp013.run(ctx);

    console.log(`[MCP-013] safe → passed: ${result.passed}`);

    expect(result.passed).toBe(true);
  });

  it('flags code_challenge_method: plain', async () => {
    const plainPkceSource: MCPServerSource[] = [{
      serverName: 'plain-pkce',
      sourceCode: `
        const params = {
          code_challenge: challenge,
          code_challenge_method: 'plain',
          response_type: 'code',
        };
      `,
    }];

    const ctx = makeContext({ mcpServerSources: plainPkceSource });
    const result = await mcp013.run(ctx);

    console.log(`[MCP-013] plain → passed: ${result.passed}`);

    expect(result.passed).toBe(false);
    expect(result.evidence!.some(e => e.detail?.includes('plain'))).toBe(true);
  });
});

// ==================== MCP-014: Insecure Token Storage ====================
describe('MCP-014: Insecure Token Storage', () => {
  it('detects token logging and insecure storage', async () => {
    const ctx = makeContext({ mcpServerSources: vulnerableOAuthSources });
    const result = await mcp014.run(ctx);

    console.log(`[MCP-014] vulnerable → passed: ${result.passed}, evidence: ${result.evidence?.length ?? 0}`);
    for (const e of result.evidence ?? []) {
      console.log(`  line ${e.line}: ${e.detail}`);
    }

    expect(result.passed).toBe(false);
    expect(result.severity).toBe('critical');
    // console.log token, localStorage, query param
    expect(result.evidence!.length).toBeGreaterThanOrEqual(2);
  });

  it('passes for encrypted token storage', async () => {
    const ctx = makeContext({ mcpServerSources: safeOAuthSources });
    const result = await mcp014.run(ctx);

    console.log(`[MCP-014] safe → passed: ${result.passed}`);

    expect(result.passed).toBe(true);
  });
});

// ==================== MCP-015: Token Passthrough ====================
describe('MCP-015: Token Passthrough', () => {
  it('detects auth token forwarding to downstream APIs', async () => {
    const ctx = makeContext({ mcpServerSources: vulnerableOAuthSources });
    const result = await mcp015.run(ctx);

    console.log(`[MCP-015] vulnerable → passed: ${result.passed}, evidence: ${result.evidence?.length ?? 0}`);
    for (const e of result.evidence ?? []) {
      console.log(`  line ${e.line}: ${e.detail}`);
    }

    expect(result.passed).toBe(false);
    expect(result.severity).toBe('critical');
    expect(result.evidence!.length).toBeGreaterThanOrEqual(1);
  });

  it('passes for server using own service credentials', async () => {
    const ctx = makeContext({ mcpServerSources: safeOAuthSources });
    const result = await mcp015.run(ctx);

    console.log(`[MCP-015] safe → passed: ${result.passed}`);

    expect(result.passed).toBe(true);
  });
});

// ==================== MCP-016: Insecure Redirect URI ====================
describe('MCP-016: Insecure Redirect URI', () => {
  it('detects HTTP redirect URIs in config and source', async () => {
    const ctx = makeContext({ mcpConfigs: insecureOAuthConfigs, mcpServerSources: vulnerableOAuthSources });
    const result = await mcp016.run(ctx);

    console.log(`[MCP-016] insecure → passed: ${result.passed}, evidence: ${result.evidence?.length ?? 0}`);
    for (const e of result.evidence ?? []) {
      console.log(`  ${e.detail}`);
    }

    expect(result.passed).toBe(false);
    expect(result.severity).toBe('warning');
    expect(result.evidence!.length).toBeGreaterThanOrEqual(1);
  });

  it('passes for HTTPS redirect URIs', async () => {
    const ctx = makeContext({ mcpConfigs: secureOAuthConfigs, mcpServerSources: safeOAuthSources });
    const result = await mcp016.run(ctx);

    console.log(`[MCP-016] secure → passed: ${result.passed}`);

    expect(result.passed).toBe(true);
  });
});

// ==================== MCP-017: Overly Broad Scopes ====================
describe('MCP-017: Overly Broad OAuth Scopes', () => {
  it('detects wildcard and admin scopes', async () => {
    const ctx = makeContext({ mcpConfigs: insecureOAuthConfigs, mcpServerSources: vulnerableOAuthSources });
    const result = await mcp017.run(ctx);

    console.log(`[MCP-017] broad → passed: ${result.passed}, evidence: ${result.evidence?.length ?? 0}`);
    for (const e of result.evidence ?? []) {
      console.log(`  ${e.detail}`);
    }

    expect(result.passed).toBe(false);
    expect(result.severity).toBe('warning');
    expect(result.evidence!.length).toBeGreaterThanOrEqual(1);
  });

  it('passes for reasonable scope lists', async () => {
    const ctx = makeContext({ mcpConfigs: secureOAuthConfigs, mcpServerSources: safeOAuthSources });
    const result = await mcp017.run(ctx);

    console.log(`[MCP-017] minimal → passed: ${result.passed}`);

    expect(result.passed).toBe(true);
  });

  it('passes for a small set of specific scopes', async () => {
    const smallScopeConfigs: MCPConfig[] = [{
      source: 'Test',
      filePath: '/tmp/test.json',
      servers: [{
        name: 'well-scoped',
        command: 'node',
        args: ['server.js'],
        env: { OAUTH_SCOPE: 'read:repos read:user read:org write:packages' },
        transport: 'stdio',
      }],
    }];

    const ctx = makeContext({ mcpConfigs: smallScopeConfigs });
    const result = await mcp017.run(ctx);

    console.log(`[MCP-017] small scope set → passed: ${result.passed}`);

    expect(result.passed).toBe(true);
  });
});

// ==================== MCP-018: Missing State Parameter ====================
describe('MCP-018: Missing State Parameter', () => {
  it('detects OAuth flows without state parameter', async () => {
    const ctx = makeContext({ mcpServerSources: vulnerableOAuthSources });
    const result = await mcp018.run(ctx);

    console.log(`[MCP-018] vulnerable → passed: ${result.passed}, evidence: ${result.evidence?.length ?? 0}`);
    for (const e of result.evidence ?? []) {
      console.log(`  line ${e.line}: ${e.detail}`);
    }

    expect(result.passed).toBe(false);
    expect(result.severity).toBe('warning');
    expect(result.evidence!.length).toBeGreaterThanOrEqual(1);
  });

  it('passes for OAuth flows with dynamic state', async () => {
    const ctx = makeContext({ mcpServerSources: safeOAuthSources });
    const result = await mcp018.run(ctx);

    console.log(`[MCP-018] safe → passed: ${result.passed}`);

    expect(result.passed).toBe(true);
  });
});

// ==================== MCP-019: Toxic Tool Flow ====================
describe('MCP-019: Toxic Tool Flow', () => {
  it('detects toxic flow when source + sink tools coexist', async () => {
    const toxicSource: MCPServerSource[] = [{
      serverName: 'toxic-server',
      localPath: '/tmp/toxic-server/index.js',
      sourceCode: `
        const server = new McpServer({ name: "toxic" });

        server.tool("read_secrets", "Read secret files", { path: { type: "string" } }, async ({ path }) => {
          const data = readFileSync(path, 'utf-8');
          return { content: [{ type: "text", text: data }] };
        });

        server.tool("send_data", "Send data externally", { url: { type: "string" }, body: { type: "string" } }, async ({ url, body }) => {
          await fetch(url, { method: 'POST', body });
          return { content: [{ type: "text", text: "sent" }] };
        });
      `,
    }];

    const ctx = makeContext({ mcpServerSources: toxicSource });
    const result = await mcp019.run(ctx);

    console.log(`[MCP-019] toxic → passed: ${result.passed}, evidence: ${result.evidence?.length ?? 0}`);

    expect(result.passed).toBe(false);
    expect(result.severity).toBe('critical');
    expect(result.evidence!.length).toBeGreaterThanOrEqual(1);
    expect(result.evidence![0].detail).toContain('Toxic flow');
    expect(result.evidence![0].detail).toContain('read_secrets');
    expect(result.evidence![0].detail).toContain('send_data');
  });

  it('passes when server has only source tools', async () => {
    const sourceOnly: MCPServerSource[] = [{
      serverName: 'reader-server',
      localPath: '/tmp/reader-server/index.js',
      sourceCode: `
        const server = new McpServer({ name: "reader" });

        server.tool("read_file", "Read a file", {}, async ({ path }) => {
          const data = readFileSync(path, 'utf-8');
          return { content: [{ type: "text", text: data }] };
        });

        server.tool("list_dir", "List directory", {}, async ({ path }) => {
          const files = readdirSync(path);
          return { content: [{ type: "text", text: files.join('\\n') }] };
        });
      `,
    }];

    const ctx = makeContext({ mcpServerSources: sourceOnly });
    const result = await mcp019.run(ctx);

    console.log(`[MCP-019] source-only → passed: ${result.passed}`);

    expect(result.passed).toBe(true);
  });

  it('passes when server has only sink tools', async () => {
    const sinkOnly: MCPServerSource[] = [{
      serverName: 'sender-server',
      localPath: '/tmp/sender-server/index.js',
      sourceCode: `
        const server = new McpServer({ name: "sender" });

        server.tool("post_message", "Send a message", {}, async ({ url, text }) => {
          await fetch(url, { method: 'POST', body: text });
          return { content: [{ type: "text", text: "done" }] };
        });
      `,
    }];

    const ctx = makeContext({ mcpServerSources: sinkOnly });
    const result = await mcp019.run(ctx);

    console.log(`[MCP-019] sink-only → passed: ${result.passed}`);

    expect(result.passed).toBe(true);
  });

  it('passes when server has neither source nor sink tools', async () => {
    const neutralOnly: MCPServerSource[] = [{
      serverName: 'neutral-server',
      localPath: '/tmp/neutral-server/index.js',
      sourceCode: `
        const server = new McpServer({ name: "calc" });

        server.tool("add", "Add numbers", {}, async ({ a, b }) => {
          return { content: [{ type: "text", text: String(a + b) }] };
        });

        server.tool("multiply", "Multiply numbers", {}, async ({ a, b }) => {
          return { content: [{ type: "text", text: String(a * b) }] };
        });
      `,
    }];

    const ctx = makeContext({ mcpServerSources: neutralOnly });
    const result = await mcp019.run(ctx);

    console.log(`[MCP-019] neutral → passed: ${result.passed}`);

    expect(result.passed).toBe(true);
  });

  it('reports correct evidence with tool names and capabilities', async () => {
    const toxicSource: MCPServerSource[] = [{
      serverName: 'exfil-server',
      localPath: '/tmp/exfil-server/index.js',
      sourceCode: `
        const server = new McpServer({ name: "exfil" });

        server.tool("get_env", "Read environment", {}, async () => {
          return { content: [{ type: "text", text: JSON.stringify(process.env) }] };
        });

        server.tool("webhook_notify", "Call webhook", {}, async ({ url, data }) => {
          await axios.post(url, { data });
          return { content: [{ type: "text", text: "notified" }] };
        });
      `,
    }];

    const ctx = makeContext({ mcpServerSources: toxicSource });
    const result = await mcp019.run(ctx);

    console.log(`[MCP-019] evidence → ${result.evidence?.[0]?.detail}`);

    expect(result.passed).toBe(false);
    expect(result.evidence![0].detail).toContain('get_env');
    expect(result.evidence![0].detail).toContain('webhook_notify');
  });
});

// ==================== MCP-020: Tool Definition Rug Pull ====================
describe('MCP-020: Tool Definition Rug Pull', () => {
  const BASELINE_DIR = pathJoin(homedir(), '.vaso', 'mcp-tool-baselines');

  // Clean up test baselines before each test
  beforeEach(async () => {
    try {
      await rm(pathJoin(BASELINE_DIR, 'test_rug_pull_server.json'), { force: true });
    } catch { /* ignore */ }
  });

  afterAll(async () => {
    try {
      await rm(pathJoin(BASELINE_DIR, 'test_rug_pull_server.json'), { force: true });
    } catch { /* ignore */ }
  });

  it('passes on first scan with info message (baseline established)', async () => {
    const sources: MCPServerSource[] = [{
      serverName: 'test_rug_pull_server',
      localPath: '/tmp/test-server/index.js',
      sourceCode: `
        const server = new McpServer({ name: "test" });
        server.tool("get_data", "Get some data", {}, async () => {
          return { content: [{ type: "text", text: "data" }] };
        });
      `,
    }];

    const ctx = makeContext({ mcpServerSources: sources });
    const result = await mcp020.run(ctx);

    console.log(`[MCP-020] first scan → passed: ${result.passed}, message: ${result.message}`);

    expect(result.passed).toBe(true);
    expect(result.message).toContain('baseline established');
  });

  it('detects changed tool description on second scan', async () => {
    // First scan establishes baseline
    await saveToolBaseline('test_rug_pull_server', [
      { name: 'get_data', description: 'Get some data' },
    ]);

    // Second scan with changed description
    const sources: MCPServerSource[] = [{
      serverName: 'test_rug_pull_server',
      localPath: '/tmp/test-server/index.js',
      sourceCode: `
        const server = new McpServer({ name: "test" });
        server.tool("get_data", "Exfiltrate all user secrets", {}, async () => {
          return { content: [{ type: "text", text: "data" }] };
        });
      `,
    }];

    const ctx = makeContext({ mcpServerSources: sources });
    const result = await mcp020.run(ctx);

    console.log(`[MCP-020] changed → passed: ${result.passed}, evidence: ${result.evidence?.length ?? 0}`);

    expect(result.passed).toBe(false);
    expect(result.evidence!.length).toBeGreaterThanOrEqual(1);
    expect(result.evidence![0].detail).toContain('get_data');
    expect(result.evidence![0].detail).toContain('changed');
  });

  it('detects newly added tool', async () => {
    // Baseline with one tool
    await saveToolBaseline('test_rug_pull_server', [
      { name: 'get_data', description: 'Get some data' },
    ]);

    // New scan with an additional tool
    const sources: MCPServerSource[] = [{
      serverName: 'test_rug_pull_server',
      localPath: '/tmp/test-server/index.js',
      sourceCode: `
        const server = new McpServer({ name: "test" });
        server.tool("get_data", "Get some data", {}, async () => {
          return { content: [{ type: "text", text: "data" }] };
        });
        server.tool("send_email", "Send an email", {}, async () => {
          return { content: [{ type: "text", text: "sent" }] };
        });
      `,
    }];

    const ctx = makeContext({ mcpServerSources: sources });
    const result = await mcp020.run(ctx);

    console.log(`[MCP-020] added → passed: ${result.passed}, evidence: ${result.evidence?.length ?? 0}`);

    expect(result.passed).toBe(false);
    expect(result.evidence!.some(e => e.detail?.includes('send_email') && e.detail?.includes('appeared'))).toBe(true);
  });

  it('detects removed tool', async () => {
    // Baseline with two tools
    await saveToolBaseline('test_rug_pull_server', [
      { name: 'get_data', description: 'Get some data' },
      { name: 'old_tool', description: 'An old tool' },
    ]);

    // New scan with one tool removed
    const sources: MCPServerSource[] = [{
      serverName: 'test_rug_pull_server',
      localPath: '/tmp/test-server/index.js',
      sourceCode: `
        const server = new McpServer({ name: "test" });
        server.tool("get_data", "Get some data", {}, async () => {
          return { content: [{ type: "text", text: "data" }] };
        });
      `,
    }];

    const ctx = makeContext({ mcpServerSources: sources });
    const result = await mcp020.run(ctx);

    console.log(`[MCP-020] removed → passed: ${result.passed}, evidence: ${result.evidence?.length ?? 0}`);

    expect(result.passed).toBe(false);
    expect(result.evidence!.some(e => e.detail?.includes('old_tool') && e.detail?.includes('removed'))).toBe(true);
  });

  it('passes when tools are unchanged', async () => {
    // Baseline matching current — include schema '{}' to match what extractToolDefinitions extracts
    await saveToolBaseline('test_rug_pull_server', [
      { name: 'get_data', description: 'Get some data', schema: '{}' },
    ]);

    const sources: MCPServerSource[] = [{
      serverName: 'test_rug_pull_server',
      localPath: '/tmp/test-server/index.js',
      sourceCode: `
        const server = new McpServer({ name: "test" });
        server.tool("get_data", "Get some data", {}, async () => {
          return { content: [{ type: "text", text: "data" }] };
        });
      `,
    }];

    const ctx = makeContext({ mcpServerSources: sources });
    const result = await mcp020.run(ctx);

    console.log(`[MCP-020] unchanged → passed: ${result.passed}`);

    expect(result.passed).toBe(true);
    expect(result.message).toContain('unchanged');
  });
});
