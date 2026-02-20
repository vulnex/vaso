import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { runDetect } from './detect.js';
import { adapterRegistry } from '../adapters/registry.js';
import type { AgentInstallation } from '../core/types.js';

const mockInstallations: AgentInstallation[] = [
  {
    agent: 'openclaw',
    version: '1.2.3',
    installDir: '/home/user/.openclaw',
    configFiles: [
      { raw: '{}', format: 'json', filePath: '/home/user/.openclaw/openclaw.json', data: {} },
      { raw: '', format: 'yaml', filePath: '/home/user/.openclaw/config.yaml', data: {} },
    ],
    skillsDir: '/home/user/.openclaw/skills',
    gateway: { host: '127.0.0.1', port: 8080, tls: true, authMode: 'token' },
  },
  {
    agent: 'nanoclaw',
    version: '0.5.0',
    installDir: '/home/user/.nanoclaw',
    configFiles: [
      { raw: '{}', format: 'json', filePath: '/home/user/.nanoclaw/config.json', data: {} },
    ],
    skillsDir: undefined,
    gateway: undefined,
  },
];

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
});

afterEach(() => {
  console.log = originalLog;
  console.error = originalError;
  vi.restoreAllMocks();
});

describe('runDetect', () => {
  it('renders detected agents in terminal format', async () => {
    vi.spyOn(adapterRegistry, 'detectAll').mockResolvedValue(mockInstallations);

    await runDetect({ format: 'terminal' });

    const output = consoleLogs.join('\n');
    expect(output).toContain('openclaw');
    expect(output).toContain('1.2.3');
    expect(output).toContain('/home/user/.openclaw');
    expect(output).toContain('2'); // config file count
    expect(output).toContain('/home/user/.openclaw/skills');
    expect(output).toContain('127.0.0.1');
    expect(output).toContain(':8080');
    expect(output).toContain('nanoclaw');
    expect(output).toContain('Found 2 agent(s).');
  });

  it('renders detected agents in JSON format', async () => {
    vi.spyOn(adapterRegistry, 'detectAll').mockResolvedValue(mockInstallations);

    await runDetect({ format: 'json' });

    const output = consoleLogs.join('\n');
    const parsed = JSON.parse(output);
    expect(parsed).toHaveLength(2);
    expect(parsed[0].agent).toBe('openclaw');
    expect(parsed[0].version).toBe('1.2.3');
    expect(parsed[1].agent).toBe('nanoclaw');
  });

  it('filters by --agent option', async () => {
    vi.spyOn(adapterRegistry, 'detectAll').mockResolvedValue(mockInstallations);

    await runDetect({ format: 'json', agent: 'nanoclaw' });

    const parsed = JSON.parse(consoleLogs.join('\n'));
    expect(parsed).toHaveLength(1);
    expect(parsed[0].agent).toBe('nanoclaw');
  });

  it('handles no agents found gracefully', async () => {
    vi.spyOn(adapterRegistry, 'detectAll').mockResolvedValue([]);

    await runDetect({ format: 'terminal' });

    const output = consoleLogs.join('\n');
    expect(output).toContain('No agents detected.');
  });

  it('verbose mode shows search paths', async () => {
    vi.spyOn(adapterRegistry, 'detectAll').mockResolvedValue([mockInstallations[0]]);
    vi.spyOn(adapterRegistry, 'getAdapters').mockReturnValue([
      {
        agent: 'openclaw',
        displayName: 'OpenClaw',
        async detect() { return null; },
        getConfigPaths() { return ['/home/user/.openclaw/openclaw.json']; },
        getSkillsDir() { return undefined; },
        getGatewayInfo() { return undefined; },
      },
    ]);

    await runDetect({ format: 'terminal', verbose: true });

    const output = consoleLogs.join('\n');
    expect(output).toContain('Adapters checked:');
    expect(output).toContain('OpenClaw');
    expect(output).toContain('/home/user/.openclaw/openclaw.json');
    expect(output).toContain('found');
  });
});
