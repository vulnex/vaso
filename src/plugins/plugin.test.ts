import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import type { ScanResult } from '../core/types.js';
import type { PluginConfig, PluginInfo } from './types.js';
import { DEFAULT_PLUGIN_CONFIG } from './types.js';

// ─── Mocks ────────────────────────────────────────────────────────

// Mock installer
const mockInstallPlugin = vi.fn();
const mockUninstallPlugin = vi.fn();
const mockGetPluginStatus = vi.fn();
vi.mock('../plugins/installer.js', () => ({
  installPlugin: (...args: unknown[]) => mockInstallPlugin(...args),
  uninstallPlugin: (...args: unknown[]) => mockUninstallPlugin(...args),
  getPluginStatus: (...args: unknown[]) => mockGetPluginStatus(...args),
  getPluginInstallPath: (agent: string) => {
    const paths: Record<string, string> = {
      openclaw: '/home/user/.openclaw/plugins/vaso-security.mjs',
      nanoclaw: '/home/user/.config/nanoclaw/plugins/vaso-security.mjs',
      picoclaw: '/home/user/.picoclaw/plugins/vaso-security.mjs',
    };
    return paths[agent];
  },
  generatePluginContent: (agent: string, binaryPath: string) => {
    // Dynamically import real function for content generation tests
    // This mock is only for CLI command tests
    return `// mock plugin for ${agent} using ${binaryPath}`;
  },
  loadPluginConfig: async () => ({ ...DEFAULT_PLUGIN_CONFIG }),
  resolveVasoBinaryPath: () => '/usr/local/bin/vaso',
}));

// Mock scan engine for runner tests
const mockScan = vi.fn();
vi.mock('../core/engine.js', () => ({
  ScanEngine: vi.fn().mockImplementation(function () {
    return { scan: mockScan };
  }),
}));

// Mock adapters
vi.mock('../adapters/registry.js', () => ({
  adapterRegistry: {
    register: vi.fn(),
  },
}));
vi.mock('../adapters/openclaw.js', () => ({ openclawAdapter: {} }));
vi.mock('../adapters/nanoclaw.js', () => ({ nanoclawAdapter: {} }));
vi.mock('../adapters/picoclaw.js', () => ({ picoclawAdapter: {} }));
vi.mock('../checks/index.js', () => ({ registerAllChecks: vi.fn() }));
vi.mock('../ioc/database.js', () => ({ initIOCDatabase: vi.fn().mockResolvedValue(undefined) }));
vi.mock('../core/check-registry.js', () => ({ checkRegistry: {} }));

// ─── Console capture ──────────────────────────────────────────────

let consoleLogs: string[];
let consoleErrorLogs: string[];
let consoleWarnLogs: string[];
const originalLog = console.log;
const originalError = console.error;
const originalWarn = console.warn;

beforeEach(() => {
  consoleLogs = [];
  consoleErrorLogs = [];
  consoleWarnLogs = [];
  console.log = (...args: unknown[]) => {
    consoleLogs.push(args.map(String).join(' '));
  };
  console.error = (...args: unknown[]) => {
    consoleErrorLogs.push(args.map(String).join(' '));
  };
  console.warn = (...args: unknown[]) => {
    consoleWarnLogs.push(args.map(String).join(' '));
  };
  process.exitCode = undefined;
  vi.clearAllMocks();
});

afterEach(() => {
  console.log = originalLog;
  console.error = originalError;
  console.warn = originalWarn;
  process.exitCode = undefined;
});

// ─── Sample data ──────────────────────────────────────────────────

function makeScanResult(overrides?: Partial<ScanResult>): ScanResult {
  return {
    timestamp: '2026-01-01T00:00:00.000Z',
    agents: [{
      agent: 'openclaw',
      installation: { agent: 'openclaw', installDir: '/tmp', configFiles: [] },
      results: [],
      score: 100,
      grade: 'A',
    }],
    totalScore: 100,
    totalGrade: 'A',
    fleetAverage: 100,
    summary: { critical: 0, warning: 0, info: 0, passed: 0, total: 0 },
    ...overrides,
  };
}

function makeResultWithFindings(): ScanResult {
  return makeScanResult({
    totalScore: 35,
    totalGrade: 'F',
    fleetAverage: 35,
    summary: { critical: 2, warning: 1, info: 1, passed: 3, total: 7 },
    agents: [{
      agent: 'openclaw',
      installation: { agent: 'openclaw', installDir: '/tmp', configFiles: [] },
      results: [
        { id: 'CFG-001', name: 'Gateway Binding', category: 'config', severity: 'critical', passed: false, message: 'Gateway bound to 0.0.0.0' },
        { id: 'CFG-002', name: 'API Key Exposure', category: 'config', severity: 'critical', passed: false, message: 'API key found in config' },
        { id: 'CFG-003', name: 'TLS Disabled', category: 'config', severity: 'warning', passed: false, message: 'TLS not enabled' },
        { id: 'CFG-004', name: 'Log Level', category: 'config', severity: 'info', passed: false, message: 'Debug logging enabled' },
        { id: 'CFG-005', name: 'Permissions', category: 'config', severity: 'critical', passed: true, message: 'Permissions OK' },
        { id: 'CFG-006', name: 'Auth Mode', category: 'config', severity: 'warning', passed: true, message: 'Auth configured' },
        { id: 'CFG-007', name: 'Config Format', category: 'config', severity: 'info', passed: true, message: 'Valid YAML' },
      ],
      score: 35,
      grade: 'F',
    }],
  });
}

// ─── evaluateScanResult ───────────────────────────────────────────

describe('evaluateScanResult', () => {
  let evaluateScanResult: typeof import('./runner.js').evaluateScanResult;

  beforeEach(async () => {
    const mod = await import('./runner.js');
    evaluateScanResult = mod.evaluateScanResult;
  });

  it('returns passed when no findings', () => {
    const result = evaluateScanResult(makeScanResult(), DEFAULT_PLUGIN_CONFIG, 100);
    expect(result.passed).toBe(true);
    expect(result.blocked).toBe(false);
    expect(result.blockReason).toBeUndefined();
    expect(result.criticalFindings).toHaveLength(0);
    expect(result.warningFindings).toHaveLength(0);
  });

  it('blocks on critical findings when blockOnCritical is true', () => {
    const scanResult = makeResultWithFindings();
    const result = evaluateScanResult(scanResult, { ...DEFAULT_PLUGIN_CONFIG, blockOnCritical: true }, 200);

    expect(result.passed).toBe(false);
    expect(result.blocked).toBe(true);
    expect(result.blockReason).toContain('2 critical');
    expect(result.criticalFindings).toHaveLength(2);
    expect(result.criticalFindings[0].id).toBe('CFG-001');
    expect(result.criticalFindings[1].id).toBe('CFG-002');
  });

  it('does not block on critical when blockOnCritical is false', () => {
    const scanResult = makeResultWithFindings();
    const result = evaluateScanResult(scanResult, { ...DEFAULT_PLUGIN_CONFIG, blockOnCritical: false }, 200);

    expect(result.passed).toBe(true);
    expect(result.blocked).toBe(false);
    expect(result.criticalFindings).toHaveLength(2);
  });

  it('blocks on warnings when blockOnWarning is true', () => {
    const scanResult = makeResultWithFindings();
    const config: PluginConfig = { ...DEFAULT_PLUGIN_CONFIG, blockOnCritical: false, blockOnWarning: true };
    const result = evaluateScanResult(scanResult, config, 150);

    expect(result.blocked).toBe(true);
    expect(result.blockReason).toContain('1 warning');
    expect(result.warningFindings).toHaveLength(1);
    expect(result.warningFindings[0].id).toBe('CFG-003');
  });

  it('excludeChecks filters out findings', () => {
    const scanResult = makeResultWithFindings();
    const config: PluginConfig = { ...DEFAULT_PLUGIN_CONFIG, excludeChecks: ['CFG-001', 'CFG-002'] };
    const result = evaluateScanResult(scanResult, config, 100);

    expect(result.passed).toBe(true);
    expect(result.blocked).toBe(false);
    expect(result.criticalFindings).toHaveLength(0);
    expect(result.warningFindings).toHaveLength(1);
  });

  it('computes correct summary counts', () => {
    const scanResult = makeResultWithFindings();
    const result = evaluateScanResult(scanResult, DEFAULT_PLUGIN_CONFIG, 100);

    expect(result.summary).toEqual({ critical: 2, warning: 1, info: 1, passed: 3, total: 7 });
  });

  it('populates findings arrays correctly', () => {
    const scanResult = makeResultWithFindings();
    const result = evaluateScanResult(scanResult, { ...DEFAULT_PLUGIN_CONFIG, blockOnCritical: false }, 100);

    expect(result.criticalFindings).toEqual([
      { id: 'CFG-001', name: 'Gateway Binding', message: 'Gateway bound to 0.0.0.0' },
      { id: 'CFG-002', name: 'API Key Exposure', message: 'API key found in config' },
    ]);
    expect(result.warningFindings).toEqual([
      { id: 'CFG-003', name: 'TLS Disabled', message: 'TLS not enabled' },
    ]);
  });

  it('includes elapsedMs in result', () => {
    const result = evaluateScanResult(makeScanResult(), DEFAULT_PLUGIN_CONFIG, 42);
    expect(result.elapsedMs).toBe(42);
  });

  it('includes score and grade from scan result', () => {
    const scanResult = makeResultWithFindings();
    const result = evaluateScanResult(scanResult, { ...DEFAULT_PLUGIN_CONFIG, blockOnCritical: false }, 100);
    expect(result.score).toBe(35);
    expect(result.grade).toBe('F');
  });

  it('blockOnCritical takes priority over blockOnWarning', () => {
    const scanResult = makeResultWithFindings();
    const config: PluginConfig = { ...DEFAULT_PLUGIN_CONFIG, blockOnCritical: true, blockOnWarning: true };
    const result = evaluateScanResult(scanResult, config, 100);

    expect(result.blocked).toBe(true);
    expect(result.blockReason).toContain('critical');
  });
});

// ─── generatePluginContent (real implementation) ──────────────────

describe('generatePluginContent', () => {
  // Import the real implementation directly from source
  let generatePluginContent: (agent: string, binaryPath: string) => string;

  beforeEach(async () => {
    // Reset modules to get the real function
    const mod = await vi.importActual<typeof import('./installer.js')>('./installer.js');
    generatePluginContent = mod.generatePluginContent as (agent: string, binaryPath: string) => string;
  });

  it('generates OpenClaw plugin with hooks.before_agent_start', () => {
    const content = generatePluginContent('openclaw', '/usr/local/bin/vaso');
    expect(content).toContain('hooks');
    expect(content).toContain('before_agent_start');
    expect(content).toContain("name: 'vaso-security'");
    expect(content).toContain('export default');
  });

  it('generates NanoClaw plugin with lifecycle.onBeforeStart', () => {
    const content = generatePluginContent('nanoclaw', '/usr/local/bin/vaso');
    expect(content).toContain('lifecycle');
    expect(content).toContain('onBeforeStart');
    expect(content).toContain("export const name = 'vaso-security'");
  });

  it('generates PicoClaw plugin with handlers.preStart', () => {
    const content = generatePluginContent('picoclaw', '/usr/local/bin/vaso');
    expect(content).toContain('handlers');
    expect(content).toContain('preStart');
    expect(content).toContain("name: 'vaso-security'");
    expect(content).toContain('export default');
  });

  it('embeds binary path in generated content', () => {
    const content = generatePluginContent('openclaw', '/custom/path/to/vaso');
    expect(content).toContain('/custom/path/to/vaso');
  });

  it('embeds version in generated content', () => {
    const content = generatePluginContent('openclaw', '/usr/local/bin/vaso');
    expect(content).toContain('0.2.1');
  });

  it('uses .mjs-compatible ESM syntax', () => {
    const content = generatePluginContent('openclaw', '/usr/local/bin/vaso');
    expect(content).toContain('import {');
    expect(content).toContain('export default');
  });

  it('includes execFileSync for subprocess scan', () => {
    const content = generatePluginContent('openclaw', '/usr/local/bin/vaso');
    expect(content).toContain('execFileSync');
    expect(content).toContain("'scan'");
    expect(content).toContain("'--agent'");
    expect(content).toContain("'--format'");
    expect(content).toContain("'json'");
  });
});

// ─── getPluginInstallPath ─────────────────────────────────────────

describe('getPluginInstallPath', () => {
  let getPluginInstallPath: (agent: string) => string;

  beforeEach(async () => {
    const mod = await vi.importActual<typeof import('./installer.js')>('./installer.js');
    getPluginInstallPath = mod.getPluginInstallPath as (agent: string) => string;
  });

  it('returns openclaw path under ~/.openclaw/plugins/', () => {
    const path = getPluginInstallPath('openclaw');
    expect(path).toContain('.openclaw');
    expect(path).toContain('plugins');
    expect(path).toContain('vaso-security.mjs');
  });

  it('returns nanoclaw path under ~/.config/nanoclaw/plugins/', () => {
    const path = getPluginInstallPath('nanoclaw');
    expect(path).toContain('.config');
    expect(path).toContain('nanoclaw');
    expect(path).toContain('plugins');
    expect(path).toContain('vaso-security.mjs');
  });

  it('returns picoclaw path under ~/.picoclaw/plugins/', () => {
    const path = getPluginInstallPath('picoclaw');
    expect(path).toContain('.picoclaw');
    expect(path).toContain('plugins');
    expect(path).toContain('vaso-security.mjs');
  });
});

// ─── loadPluginConfig ─────────────────────────────────────────────

describe('loadPluginConfig', () => {
  let loadPluginConfig: () => Promise<PluginConfig>;

  beforeEach(async () => {
    const mod = await vi.importActual<typeof import('./installer.js')>('./installer.js');
    loadPluginConfig = mod.loadPluginConfig;
  });

  it('returns defaults when config file is missing', async () => {
    // Default behavior — ~/.vaso/plugin-config.json won't exist in test env
    const config = await loadPluginConfig();
    expect(config).toEqual(DEFAULT_PLUGIN_CONFIG);
  });
});

// ─── CLI: runPluginInstall ────────────────────────────────────────

describe('runPluginInstall', () => {
  let runPluginInstall: typeof import('../commands/plugin.js').runPluginInstall;

  beforeEach(async () => {
    const mod = await import('../commands/plugin.js');
    runPluginInstall = mod.runPluginInstall;
  });

  it('rejects invalid agent', async () => {
    await runPluginInstall({ agent: 'invalid' });

    const output = consoleErrorLogs.join('\n');
    expect(output).toContain('Invalid agent');
    expect(process.exitCode).toBe(1);
  });

  it('calls installPlugin and prints path on success', async () => {
    mockInstallPlugin.mockResolvedValue({
      pluginPath: '/home/user/.openclaw/plugins/vaso-security.mjs',
      manifestPath: '/home/user/.openclaw/plugins/vaso-plugin-manifest.json',
    });

    await runPluginInstall({ agent: 'openclaw' });

    expect(mockInstallPlugin).toHaveBeenCalledWith('openclaw', { force: undefined });
    const output = consoleLogs.join('\n');
    expect(output).toContain('installed');
    expect(output).toContain('openclaw');
  });

  it('suggests --force on conflict', async () => {
    mockInstallPlugin.mockRejectedValue(new Error('Plugin already installed at /path. Use --force to overwrite.'));

    await runPluginInstall({ agent: 'openclaw' });

    const output = consoleErrorLogs.join('\n');
    expect(output).toContain('already installed');
    expect(output).toContain('--force');
    expect(process.exitCode).toBe(1);
  });

  it('passes force option through', async () => {
    mockInstallPlugin.mockResolvedValue({
      pluginPath: '/path/vaso-security.mjs',
      manifestPath: '/path/vaso-plugin-manifest.json',
    });

    await runPluginInstall({ agent: 'openclaw', force: true });

    expect(mockInstallPlugin).toHaveBeenCalledWith('openclaw', { force: true });
  });
});

// ─── CLI: runPluginUninstall ──────────────────────────────────────

describe('runPluginUninstall', () => {
  let runPluginUninstall: typeof import('../commands/plugin.js').runPluginUninstall;

  beforeEach(async () => {
    const mod = await import('../commands/plugin.js');
    runPluginUninstall = mod.runPluginUninstall;
  });

  it('rejects invalid agent', async () => {
    await runPluginUninstall({ agent: 'bad' });

    const output = consoleErrorLogs.join('\n');
    expect(output).toContain('Invalid agent');
    expect(process.exitCode).toBe(1);
  });

  it('calls uninstallPlugin and prints confirmation', async () => {
    mockUninstallPlugin.mockResolvedValue(undefined);

    await runPluginUninstall({ agent: 'nanoclaw' });

    expect(mockUninstallPlugin).toHaveBeenCalledWith('nanoclaw');
    const output = consoleLogs.join('\n');
    expect(output).toContain('uninstalled');
    expect(output).toContain('nanoclaw');
  });
});

// ─── CLI: runPluginStatus ─────────────────────────────────────────

describe('runPluginStatus', () => {
  let runPluginStatus: typeof import('../commands/plugin.js').runPluginStatus;

  beforeEach(async () => {
    const mod = await import('../commands/plugin.js');
    runPluginStatus = mod.runPluginStatus;
  });

  const installedStatus: PluginInfo[] = [
    {
      agent: 'openclaw',
      installed: true,
      pluginPath: '/home/user/.openclaw/plugins/vaso-security.mjs',
      vasoBinaryPath: '/usr/local/bin/vaso',
      installedAt: '2026-01-15T10:30:00.000Z',
    },
    {
      agent: 'nanoclaw',
      installed: false,
      pluginPath: undefined,
      vasoBinaryPath: undefined,
      installedAt: undefined,
    },
    {
      agent: 'picoclaw',
      installed: false,
      pluginPath: undefined,
      vasoBinaryPath: undefined,
      installedAt: undefined,
    },
  ];

  it('renders terminal output with installed/not-installed status', async () => {
    mockGetPluginStatus.mockResolvedValue(installedStatus);

    await runPluginStatus({});

    const output = consoleLogs.join('\n');
    expect(output).toContain('Plugin Status');
    expect(output).toContain('openclaw');
    expect(output).toContain('installed');
    expect(output).toContain('nanoclaw');
    expect(output).toContain('not installed');
  });

  it('renders JSON output', async () => {
    mockGetPluginStatus.mockResolvedValue(installedStatus);

    await runPluginStatus({ format: 'json' });

    const output = consoleLogs.join('\n');
    const parsed = JSON.parse(output);
    expect(parsed).toHaveLength(3);
    expect(parsed[0].agent).toBe('openclaw');
    expect(parsed[0].installed).toBe(true);
    expect(parsed[1].installed).toBe(false);
  });

  it('shows plugin path for installed agents', async () => {
    mockGetPluginStatus.mockResolvedValue(installedStatus);

    await runPluginStatus({});

    const output = consoleLogs.join('\n');
    expect(output).toContain('.openclaw/plugins/vaso-security.mjs');
  });

  it('passes agent filter to getPluginStatus', async () => {
    mockGetPluginStatus.mockResolvedValue([installedStatus[0]]);

    await runPluginStatus({ agent: 'openclaw' });

    expect(mockGetPluginStatus).toHaveBeenCalledWith('openclaw');
  });
});

// ─── runPreStartScan ──────────────────────────────────────────────

describe('runPreStartScan', () => {
  let runPreStartScan: typeof import('./runner.js').runPreStartScan;
  let _resetForTesting: typeof import('./runner.js')._resetForTesting;

  beforeEach(async () => {
    const mod = await import('./runner.js');
    runPreStartScan = mod.runPreStartScan;
    _resetForTesting = mod._resetForTesting;
    _resetForTesting();
  });

  it('returns blocked result when critical findings exist', async () => {
    mockScan.mockResolvedValue(makeResultWithFindings());

    const result = await runPreStartScan('openclaw');

    expect(result.blocked).toBe(true);
    expect(result.passed).toBe(false);
    expect(result.criticalFindings.length).toBeGreaterThan(0);
  });

  it('returns safe result on scan error', async () => {
    mockScan.mockRejectedValue(new Error('Adapter not found'));

    const result = await runPreStartScan('openclaw');

    expect(result.passed).toBe(true);
    expect(result.blocked).toBe(false);
    expect(result.elapsedMs).toBeGreaterThanOrEqual(0);
  });

  it('returns safe result on timeout', async () => {
    mockScan.mockImplementation(() => new Promise(() => {
      // Never resolves
    }));

    const result = await runPreStartScan('openclaw', { timeout: 50 });

    expect(result.passed).toBe(true);
    expect(result.blocked).toBe(false);
  });

  it('initialization is idempotent', async () => {
    mockScan.mockResolvedValue(makeScanResult());

    await runPreStartScan('openclaw');
    await runPreStartScan('openclaw');

    // The initialization should only happen once (adapters registered once)
    const { adapterRegistry } = await import('../adapters/registry.js');
    // register is called 3 times (openclaw, nanoclaw, picoclaw) on first init only
    expect(vi.mocked(adapterRegistry.register)).toHaveBeenCalledTimes(3);
  });

  it('passes agent filter to scan engine', async () => {
    mockScan.mockResolvedValue(makeScanResult());

    await runPreStartScan('picoclaw');

    expect(mockScan).toHaveBeenCalledWith({ agentFilter: 'picoclaw' });
  });

  it('respects custom config', async () => {
    mockScan.mockResolvedValue(makeResultWithFindings());

    const result = await runPreStartScan('openclaw', { blockOnCritical: false });

    expect(result.blocked).toBe(false);
    expect(result.passed).toBe(true);
  });
});
