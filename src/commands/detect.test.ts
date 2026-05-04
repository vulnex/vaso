import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
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
    originalLog(`[detect] terminal output:\n${output}`);
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
    originalLog(`[detect] JSON output → ${parsed.length} agents: ${parsed.map((a: { agent: string }) => a.agent).join(', ')}`);
    expect(parsed).toHaveLength(2);
    expect(parsed[0].agent).toBe('openclaw');
    expect(parsed[0].version).toBe('1.2.3');
    expect(parsed[1].agent).toBe('nanoclaw');
  });

  it('filters by --agent option', async () => {
    vi.spyOn(adapterRegistry, 'detectAll').mockResolvedValue(mockInstallations);

    await runDetect({ format: 'json', agent: 'nanoclaw' });

    const parsed = JSON.parse(consoleLogs.join('\n'));
    originalLog(`[detect] --agent=nanoclaw → ${parsed.length} result(s): ${parsed.map((a: { agent: string }) => a.agent).join(', ')}`);
    expect(parsed).toHaveLength(1);
    expect(parsed[0].agent).toBe('nanoclaw');
  });

  it('handles no agents found gracefully', async () => {
    vi.spyOn(adapterRegistry, 'detectAll').mockResolvedValue([]);

    await runDetect({ format: 'terminal' });

    const output = consoleLogs.join('\n');
    originalLog(`[detect] no agents → output: "${output}"`);
    expect(output).toContain('No agents detected.');
  });

  it('writes JSON output to file when -o is set', async () => {
    vi.spyOn(adapterRegistry, 'detectAll').mockResolvedValue(mockInstallations);

    const dir = await mkdtemp(join(tmpdir(), 'vaso-detect-out-'));
    const outPath = join(dir, 'detect.json');

    try {
      await runDetect({ format: 'json', output: outPath });

      const written = await readFile(outPath, 'utf-8');
      const parsed = JSON.parse(written);
      originalLog(`[detect] -o JSON file → ${parsed.length} agents in ${outPath}`);
      expect(parsed).toHaveLength(2);
      expect(parsed[0].agent).toBe('openclaw');
      expect(parsed[1].agent).toBe('nanoclaw');

      const stdout = consoleLogs.join('\n');
      expect(stdout).toContain(`Report written to ${outPath}`);
      expect(stdout).not.toContain('"agent":');
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('writes terminal output to file when -o is set', async () => {
    vi.spyOn(adapterRegistry, 'detectAll').mockResolvedValue(mockInstallations);

    const dir = await mkdtemp(join(tmpdir(), 'vaso-detect-out-'));
    const outPath = join(dir, 'detect.txt');

    try {
      await runDetect({ format: 'terminal', output: outPath });

      const written = await readFile(outPath, 'utf-8');
      originalLog(`[detect] -o terminal file → ${written.length} bytes in ${outPath}`);
      expect(written).toContain('openclaw');
      expect(written).toContain('nanoclaw');
      expect(written).toContain('Found 2 agent(s).');

      const stdout = consoleLogs.join('\n');
      expect(stdout).toContain(`Report written to ${outPath}`);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
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
    originalLog(`[detect] verbose output:\n${output}`);
    expect(output).toContain('Adapters checked:');
    expect(output).toContain('OpenClaw');
    expect(output).toContain('/home/user/.openclaw/openclaw.json');
    expect(output).toContain('found');
  });
});
