import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { runMCPScan, runMCPList } from './mcp.js';
import type { MCPDiscoveryResult, MCPConfig } from '../mcp/types.js';
import type { ScanResult } from '../core/types.js';

// Mock MCPDiscovery
const mockDiscover = vi.fn();
const mockDiscoverFromPaths = vi.fn();
vi.mock('../mcp/discovery.js', () => ({
  MCPDiscovery: vi.fn().mockImplementation(function () {
    return {
      discover: mockDiscover,
      discoverFromPaths: mockDiscoverFromPaths,
    };
  }),
}));

// Mock resolveServerSources
const mockResolveServerSources = vi.fn().mockResolvedValue([]);
const mockResolveSourcePaths = vi.fn().mockResolvedValue({ sources: [], unreadable: [] });
vi.mock('../mcp/source-resolver.js', () => ({
  resolveServerSources: (...args: unknown[]) => mockResolveServerSources(...args),
  resolveSourcePaths: (...args: unknown[]) => mockResolveSourcePaths(...args),
}));

// Mock the OSV lookup (network)
const mockAuditDependencies = vi.fn();
vi.mock('../mcp/osv-audit.js', () => ({
  auditDependencies: (...args: unknown[]) => mockAuditDependencies(...args),
}));

// Mock ScanEngine
const mockScanMCP = vi.fn();
vi.mock('../core/engine.js', () => ({
  ScanEngine: vi.fn().mockImplementation(function () {
    return { scanMCP: mockScanMCP };
  }),
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
  fleetAverage: 100,
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
  it('looks dependencies up in OSV only with --audit-deps, and keeps scanning when OSV fails', async () => {
    mockDiscoverFromPaths.mockResolvedValue(sampleDiscoveryResult);
    const sources = [{ serverName: 'filesystem', dependencies: [{ name: 'lodash', ecosystem: 'npm', version: '4.17.20', source: 'p' }] }];
    mockResolveServerSources.mockResolvedValue(sources);
    mockScanMCP.mockResolvedValue(sampleScanResult);
    mockAuditDependencies.mockReset();

    await runMCPScan({ format: 'json', path: ['/home/user/config.json'] });
    expect(mockAuditDependencies).not.toHaveBeenCalled();

    mockAuditDependencies.mockResolvedValue({ queried: 1, vulnerable: 0, rangeOnly: 0, error: 'OSV returned HTTP 503' });
    await runMCPScan({ format: 'json', path: ['/home/user/config.json'], auditDeps: true });
    expect(mockAuditDependencies).toHaveBeenCalledWith(sources);
    expect(mockScanMCP).toHaveBeenLastCalledWith(sampleDiscoveryResult.configs, sources, expect.anything(), []);
  });

  it('scans servers discovered from explicit path', async () => {
    mockDiscoverFromPaths.mockResolvedValue(sampleDiscoveryResult);
    mockResolveServerSources.mockResolvedValue([
      { serverName: 'filesystem', packageName: '@modelcontextprotocol/server-filesystem@1.2.0' },
      { serverName: 'github', packageName: '@modelcontextprotocol/server-github@0.5.1' },
    ]);
    mockScanMCP.mockResolvedValue(sampleScanResult);

    await runMCPScan({ format: 'json', path: ['/home/user/config.json'] });

    expect(mockDiscoverFromPaths).toHaveBeenCalledWith(['/home/user/config.json']);
    expect(mockResolveServerSources).toHaveBeenCalledWith(sampleConfig.servers, { resolvePackages: undefined });
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

  it('prints message and returns when no servers found (terminal)', async () => {
    mockDiscoverFromPaths.mockResolvedValue(emptyDiscoveryResult);

    await runMCPScan({ format: 'terminal', path: ['/nonexistent'] });

    const output = consoleErrorLogs.join('\n');
    expect(output).toContain('No MCP servers found');
    expect(mockScanMCP).not.toHaveBeenCalled();
  });

  it('still writes a (clean) machine-readable report when no servers found', async () => {
    mockDiscoverFromPaths.mockResolvedValue(emptyDiscoveryResult);
    mockScanMCP.mockResolvedValue(sampleScanResult);

    await runMCPScan({ format: 'json', path: ['/nonexistent'] });

    expect(consoleErrorLogs.join('\n')).toContain('No MCP servers found');
    expect(mockScanMCP).toHaveBeenCalled();
  });

  it('exits 2 when an explicit --path is missing or unparseable (not a silent "nothing found")', async () => {
    mockDiscoverFromPaths.mockResolvedValue({ ...emptyDiscoveryResult, unreadable: ['/nonexistent/mcp.json'] });

    await runMCPScan({ format: 'json', path: ['/nonexistent/mcp.json'] });

    expect(process.exitCode).toBe(2);
    expect(consoleErrorLogs.join('\n')).toContain('Cannot read MCP config (missing or not valid JSON): /nonexistent/mcp.json');
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

  it('honours --fail-on (warning findings, none, invalid level)', async () => {
    mockDiscoverFromPaths.mockResolvedValue(sampleDiscoveryResult);
    mockResolveServerSources.mockResolvedValue([]);
    mockScanMCP.mockResolvedValue({
      ...sampleScanResult,
      agents: [{
        ...sampleScanResult.agents[0],
        results: [{ id: 'MCP-010', name: 'Rug pull', category: 'mcp', severity: 'warning', passed: false, message: 'unpinned' }],
      }],
    });
    await runMCPScan({ format: 'json', path: ['/config.json'] });
    expect(process.exitCode).toBeUndefined();
    await runMCPScan({ format: 'json', path: ['/config.json'], failOn: 'warning' });
    expect(process.exitCode).toBe(1);
    process.exitCode = undefined;
    await runMCPScan({ format: 'json', path: ['/config.json'], failOn: 'nope' });
    expect(process.exitCode).toBe(2);
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

  it('exits 2 and prints no JSON when an explicit --path is unreadable', async () => {
    mockDiscoverFromPaths.mockResolvedValue({ ...sampleDiscoveryResult, unreadable: ['/bad.json'] });

    await runMCPList({ format: 'json', path: ['/config.json', '/bad.json'] });

    expect(process.exitCode).toBe(2);
    expect(consoleLogs.join('\n')).toBe('');
  });

  it('uses platform discovery when no path given', async () => {
    mockDiscover.mockResolvedValue(sampleDiscoveryResult);

    await runMCPList({ format: 'json' });

    expect(mockDiscover).toHaveBeenCalledWith(process.platform, process.cwd());
    expect(mockDiscoverFromPaths).not.toHaveBeenCalled();
  });
});

describe('runMCPScan --source', () => {
  const direct = { serverName: 'my-server', localPath: '/src/my-server/index.js', sourceCode: 'x' };

  it('scans only the given source, without config discovery', async () => {
    mockResolveSourcePaths.mockResolvedValue({ sources: [direct], unreadable: [] });
    mockResolveServerSources.mockResolvedValue([]);
    mockScanMCP.mockResolvedValue(sampleScanResult);

    await runMCPScan({ format: 'json', source: ['/src/my-server'] });

    expect(mockDiscover).not.toHaveBeenCalled();
    expect(mockDiscoverFromPaths).not.toHaveBeenCalled();
    expect(mockResolveSourcePaths).toHaveBeenCalledWith(['/src/my-server']);
    expect(mockScanMCP).toHaveBeenCalledWith([], [direct], expect.anything(), []);
  });

  it('adds the source to the servers of the configs given with -p', async () => {
    mockDiscoverFromPaths.mockResolvedValue(sampleDiscoveryResult);
    mockResolveServerSources.mockResolvedValue([{ serverName: 'filesystem' }]);
    mockResolveSourcePaths.mockResolvedValue({ sources: [direct], unreadable: [] });
    mockScanMCP.mockResolvedValue(sampleScanResult);

    await runMCPScan({ format: 'json', path: ['/home/user/config.json'], source: ['/src/my-server'] });

    expect(mockScanMCP).toHaveBeenCalledWith(sampleDiscoveryResult.configs, [{ serverName: 'filesystem' }, direct], expect.anything(), []);
  });

  it('exits 2 when a source path holds no server source', async () => {
    mockResolveSourcePaths.mockResolvedValue({ sources: [], unreadable: ['/src/typo'] });

    await runMCPScan({ format: 'json', source: ['/src/typo'] });

    expect(process.exitCode).toBe(2);
    expect(consoleErrorLogs.join('\n')).toContain('No MCP server source at: /src/typo');
    expect(mockScanMCP).not.toHaveBeenCalled();
  });

  it('scans the readable sources when one --source path is bad, and exits 3 (incomplete)', async () => {
    mockResolveSourcePaths.mockResolvedValue({ sources: [direct], unreadable: ['/src/typo'] });
    mockResolveServerSources.mockResolvedValue([]);
    mockScanMCP.mockResolvedValue(sampleScanResult);

    await runMCPScan({ format: 'json', source: ['/src/my-server', '/src/typo'] });

    expect(mockScanMCP).toHaveBeenCalledWith([], [direct], expect.anything(), []);
    expect(consoleErrorLogs.join('\n')).toContain('No MCP server source at: /src/typo');
    expect(process.exitCode).toBe(3);
  });

  it('warns about a -p file that holds no MCP servers', async () => {
    mockDiscoverFromPaths.mockResolvedValue({ ...sampleDiscoveryResult, empty: ['/home/user/other.json'] });
    mockResolveServerSources.mockResolvedValue([]);
    mockScanMCP.mockResolvedValue(sampleScanResult);

    await runMCPScan({ format: 'json', path: ['/home/user/config.json', '/home/user/other.json'] });

    expect(consoleErrorLogs.join('\n')).toContain('No MCP servers found in /home/user/other.json');
    expect(mockScanMCP).toHaveBeenCalled();
  });
});
