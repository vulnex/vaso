import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { runMCPScan, runMCPList } from './mcp.js';
import type { MCPDiscoveryResult, MCPConfig } from '../mcp/types.js';
import type { ScanResult } from '../core/types.js';

// Mock MCPDiscovery
const mockDiscover = vi.fn();
const mockDiscoverFromPaths = vi.fn();
vi.mock('../mcp/discovery.js', () => ({
  MCPDiscovery: vi.fn().mockImplementation(() => ({
    discover: mockDiscover,
    discoverFromPaths: mockDiscoverFromPaths,
  })),
}));

// Mock resolveServerSources
const mockResolveServerSources = vi.fn().mockResolvedValue([]);
vi.mock('../mcp/source-resolver.js', () => ({
  resolveServerSources: (...args: unknown[]) => mockResolveServerSources(...args),
}));

// Mock ScanEngine
const mockScanMCP = vi.fn();
vi.mock('../core/engine.js', () => ({
  ScanEngine: vi.fn().mockImplementation(() => ({
    scanMCP: mockScanMCP,
  })),
}));

// Mock getReporter
const mockRender = vi.fn().mockReturnValue('rendered output');
vi.mock('../reporting/index.js', () => ({
  getReporter: vi.fn().mockReturnValue({
    render: (...args: unknown[]) => mockRender(...args),
  }),
}));

const sampleConfig: MCPConfig = {
  source: 'Claude Desktop',
  filePath: '/home/user/.config/Claude/claude_desktop_config.json',
  servers: [
    { name: 'filesystem', command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystem@1.2.0'], transport: 'stdio' },
    { name: 'github', command: 'npx', args: ['-y', '@modelcontextprotocol/server-github@0.5.1'], env: { GITHUB_TOKEN: '${GITHUB_TOKEN}' }, transport: 'stdio' },
  ],
};

const sampleDiscoveryResult: MCPDiscoveryResult = {
  configs: [sampleConfig],
  totalServers: 2,
};

const emptyDiscoveryResult: MCPDiscoveryResult = {
  configs: [],
  totalServers: 0,
};

const sampleScanResult: ScanResult = {
  timestamp: '2026-01-01T00:00:00.000Z',
  agents: [
    {
      agent: 'mcp',
      installation: { agent: 'mcp', installDir: '/tmp', configFiles: [] },
      results: [
        { id: 'MCP-001', name: 'MCP Config Discovery', category: 'mcp', severity: 'info', passed: true, message: 'Found 2 MCP servers' },
        { id: 'MCP-002', name: 'Transport Security', category: 'mcp', severity: 'critical', passed: true, message: 'All transports secure' },
      ],
      score: 100,
      grade: 'A',
    },
  ],
  totalScore: 100,
  totalGrade: 'A',
  summary: { critical: 0, warning: 0, info: 1, passed: 2, total: 2 },
};

let consoleLogs: string[];
let consoleErrorLogs: string[];
const originalLog = console.log;
const originalError = console.error;

beforeEach(() => {
  consoleLogs = [];
  consoleErrorLogs = [];
  console.log = (...args: unknown[]) => {
    consoleLogs.push(args.map(String).join(' '));
  };
  console.error = (...args: unknown[]) => {
    consoleErrorLogs.push(args.map(String).join(' '));
  };
  process.exitCode = undefined;

  vi.clearAllMocks();
  mockRender.mockReturnValue('rendered output');
});

afterEach(() => {
  console.log = originalLog;
  console.error = originalError;
  process.exitCode = undefined;
});

describe('runMCPScan', () => {
  it('scans servers discovered from explicit path', async () => {
    mockDiscoverFromPaths.mockResolvedValue(sampleDiscoveryResult);
    mockResolveServerSources.mockResolvedValue([
      { serverName: 'filesystem', packageName: '@modelcontextprotocol/server-filesystem@1.2.0' },
      { serverName: 'github', packageName: '@modelcontextprotocol/server-github@0.5.1' },
    ]);
    mockScanMCP.mockResolvedValue(sampleScanResult);

    await runMCPScan({ format: 'json', path: ['/home/user/config.json'] });

    expect(mockDiscoverFromPaths).toHaveBeenCalledWith(['/home/user/config.json']);
    expect(mockResolveServerSources).toHaveBeenCalledWith(sampleConfig.servers);
    expect(mockScanMCP).toHaveBeenCalled();
    const output = consoleLogs.join('\n');
    expect(output).toContain('rendered output');
  });

  it('uses platform discovery when no path given', async () => {
    mockDiscover.mockResolvedValue(sampleDiscoveryResult);
    mockResolveServerSources.mockResolvedValue([]);
    mockScanMCP.mockResolvedValue(sampleScanResult);

    await runMCPScan({ format: 'terminal' });

    expect(mockDiscover).toHaveBeenCalledWith(process.platform, process.cwd());
    expect(mockDiscoverFromPaths).not.toHaveBeenCalled();
  });

  it('prints message and returns when no servers found', async () => {
    mockDiscoverFromPaths.mockResolvedValue(emptyDiscoveryResult);

    await runMCPScan({ format: 'json', path: ['/nonexistent'] });

    const output = consoleLogs.join('\n');
    expect(output).toContain('No MCP servers found');
    expect(mockScanMCP).not.toHaveBeenCalled();
  });

  it('sets exitCode=1 on critical failures', async () => {
    mockDiscoverFromPaths.mockResolvedValue(sampleDiscoveryResult);
    mockResolveServerSources.mockResolvedValue([]);
    const failResult: ScanResult = {
      ...sampleScanResult,
      agents: [{
        ...sampleScanResult.agents[0],
        results: [
          { id: 'MCP-002', name: 'Transport Security', category: 'mcp', severity: 'critical', passed: false, message: 'HTTP on 0.0.0.0' },
        ],
      }],
    };
    mockScanMCP.mockResolvedValue(failResult);

    await runMCPScan({ format: 'json', path: ['/config.json'] });

    expect(process.exitCode).toBe(1);
  });
});

describe('runMCPList', () => {
  it('outputs JSON when format is json', async () => {
    mockDiscoverFromPaths.mockResolvedValue(sampleDiscoveryResult);

    await runMCPList({ format: 'json', path: ['/config.json'] });

    const output = consoleLogs.join('\n');
    const parsed = JSON.parse(output);
    expect(parsed.totalServers).toBe(2);
    expect(parsed.configs).toHaveLength(1);
    expect(parsed.configs[0].servers).toHaveLength(2);
  });

  it('outputs formatted text when format is terminal', async () => {
    mockDiscoverFromPaths.mockResolvedValue(sampleDiscoveryResult);

    await runMCPList({ format: 'terminal', path: ['/config.json'] });

    const output = consoleLogs.join('\n');
    expect(output).toContain('MCP Servers');
    expect(output).toContain('2 total');
    expect(output).toContain('filesystem');
    expect(output).toContain('github');
    expect(output).toContain('stdio');
  });

  it('prints message when no servers found', async () => {
    mockDiscoverFromPaths.mockResolvedValue(emptyDiscoveryResult);

    await runMCPList({ format: 'terminal', path: ['/nonexistent'] });

    const output = consoleLogs.join('\n');
    expect(output).toContain('No MCP servers found');
  });

  it('uses platform discovery when no path given', async () => {
    mockDiscover.mockResolvedValue(sampleDiscoveryResult);

    await runMCPList({ format: 'json' });

    expect(mockDiscover).toHaveBeenCalledWith(process.platform, process.cwd());
    expect(mockDiscoverFromPaths).not.toHaveBeenCalled();
  });
});
