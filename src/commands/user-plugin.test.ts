import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

vi.mock('../user-plugins/loader.js', () => ({
  getLoadedPlugins: vi.fn(),
}));

import { getLoadedPlugins } from '../user-plugins/loader.js';
import { runExtList, runExtInfo } from './user-plugin.js';
import type { LoadedPlugin } from '../user-plugins/types.js';

const mockGetLoadedPlugins = vi.mocked(getLoadedPlugins);

function makePlugin(overrides?: Partial<LoadedPlugin>): LoadedPlugin {
  return {
    path: '/home/testuser/.vaso/plugins/my-plugin.mjs',
    name: 'my-plugin',
    version: '1.0.0',
    description: 'A test plugin',
    status: 'loaded',
    registered: { checks: ['CUSTOM-001'], adapters: [], reporters: [] },
    ...overrides,
  };
}

describe('runExtList', () => {
  let consoleLogs: string[];

  beforeEach(() => {
    vi.resetAllMocks();
    consoleLogs = [];
    vi.spyOn(console, 'log').mockImplementation((...args: unknown[]) => {
      consoleLogs.push(args.map(String).join(' '));
    });
  });

  it('shows help message when no plugins', async () => {
    mockGetLoadedPlugins.mockReturnValue([]);
    await runExtList({});
    expect(consoleLogs.some(l => l.includes('No user plugins loaded'))).toBe(true);
    expect(consoleLogs.some(l => l.includes('~/.vaso/plugins/'))).toBe(true);
  });

  it('renders plugin list', async () => {
    mockGetLoadedPlugins.mockReturnValue([makePlugin()]);
    await runExtList({});
    expect(consoleLogs.some(l => l.includes('my-plugin'))).toBe(true);
    expect(consoleLogs.some(l => l.includes('loaded'))).toBe(true);
  });

  it('outputs JSON format', async () => {
    const plugin = makePlugin();
    mockGetLoadedPlugins.mockReturnValue([plugin]);
    await runExtList({ format: 'json' });
    const jsonLine = consoleLogs.find(l => l.startsWith('['));
    expect(jsonLine).toBeDefined();
    const parsed = JSON.parse(jsonLine!);
    expect(parsed).toHaveLength(1);
    expect(parsed[0].name).toBe('my-plugin');
  });

  it('shows error status', async () => {
    mockGetLoadedPlugins.mockReturnValue([makePlugin({ status: 'error', error: 'Load failed' })]);
    await runExtList({});
    expect(consoleLogs.some(l => l.includes('error'))).toBe(true);
    expect(consoleLogs.some(l => l.includes('Load failed'))).toBe(true);
  });

  it('shows registered counts', async () => {
    mockGetLoadedPlugins.mockReturnValue([makePlugin({ registered: { checks: ['A', 'B'], adapters: ['MyAgent'], reporters: [] } })]);
    await runExtList({});
    expect(consoleLogs.some(l => l.includes('2 checks'))).toBe(true);
    expect(consoleLogs.some(l => l.includes('1 adapter'))).toBe(true);
  });
});

describe('runExtInfo', () => {
  let consoleLogs: string[];
  let consoleErrors: string[];
  const origExitCode = process.exitCode;

  beforeEach(() => {
    vi.resetAllMocks();
    process.exitCode = undefined;
    consoleLogs = [];
    consoleErrors = [];
    vi.spyOn(console, 'log').mockImplementation((...args: unknown[]) => {
      consoleLogs.push(args.map(String).join(' '));
    });
    vi.spyOn(console, 'error').mockImplementation((...args: unknown[]) => {
      consoleErrors.push(args.map(String).join(' '));
    });
  });

  afterEach(() => {
    process.exitCode = origExitCode;
  });

  it('shows plugin details', async () => {
    mockGetLoadedPlugins.mockReturnValue([makePlugin()]);
    await runExtInfo('my-plugin', {});
    expect(consoleLogs.some(l => l.includes('my-plugin'))).toBe(true);
    expect(consoleLogs.some(l => l.includes('loaded'))).toBe(true);
    expect(consoleLogs.some(l => l.includes('1.0.0'))).toBe(true);
  });

  it('sets exit code 1 when not found', async () => {
    mockGetLoadedPlugins.mockReturnValue([]);
    await runExtInfo('nonexistent', {});
    expect(process.exitCode).toBe(1);
    expect(consoleErrors.some(l => l.includes('not found'))).toBe(true);
  });

  it('outputs JSON format for plugin details', async () => {
    const plugin = makePlugin();
    mockGetLoadedPlugins.mockReturnValue([plugin]);
    await runExtInfo('my-plugin', { format: 'json' });
    const jsonLine = consoleLogs.find(l => l.startsWith('{'));
    expect(jsonLine).toBeDefined();
    const parsed = JSON.parse(jsonLine!);
    expect(parsed.name).toBe('my-plugin');
  });

  it('outputs JSON error when not found in JSON mode', async () => {
    mockGetLoadedPlugins.mockReturnValue([]);
    await runExtInfo('missing', { format: 'json' });
    const jsonLine = consoleLogs.find(l => l.includes('"error"'));
    expect(jsonLine).toBeDefined();
    expect(process.exitCode).toBe(1);
  });

  it('shows registered checks section', async () => {
    mockGetLoadedPlugins.mockReturnValue([makePlugin()]);
    await runExtInfo('my-plugin', {});
    expect(consoleLogs.some(l => l.includes('Checks:'))).toBe(true);
    expect(consoleLogs.some(l => l.includes('CUSTOM-001'))).toBe(true);
  });

  it('shows error field', async () => {
    mockGetLoadedPlugins.mockReturnValue([makePlugin({ status: 'error', error: 'Something went wrong' })]);
    await runExtInfo('my-plugin', {});
    expect(consoleLogs.some(l => l.includes('Error:'))).toBe(true);
    expect(consoleLogs.some(l => l.includes('Something went wrong'))).toBe(true);
  });
});
