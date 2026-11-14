import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
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

  it('lists every skills directory with skill counts, and names skills under --verbose', async () => {
    const root = await mkdtemp(join(tmpdir(), 'vaso-detect-skills-'));
    try {
      const { mkdir } = await import('node:fs/promises');
      await mkdir(join(root, 'skills', 'pdf'), { recursive: true });
      await writeFile(join(root, 'skills', 'pdf', 'SKILL.md'), '---\nname: pdf-tools\n---\n');
      await writeFile(join(root, 'skills', 'pdf', 'fill.py'), 'print(1)');
      await mkdir(join(root, 'skills', 'helper'));
      await writeFile(join(root, 'skills', 'helper', 'run.js'), '1');
      const inst: AgentInstallation = {
        agent: 'codex',
        installDir: root,
        configFiles: [],
        skillsDirs: [join(root, 'skills'), join(root, 'missing')],
      };
      vi.spyOn(adapterRegistry, 'detectAll').mockResolvedValue([inst]);

      await runDetect({ format: 'terminal', verbose: true });
      const output = consoleLogs.join('\n');
      expect(output).toContain(join(root, 'skills'));
      expect(output).toMatch(new RegExp(`${join(root, 'missing').replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}.*not present`));
      expect(output).toMatch(/Skills:\s+1 .*\+1 other entry/);
      expect(output).toContain('pdf-tools');
      expect(output).toContain('(no SKILL.md)');

      consoleLogs = [];
      await runDetect({ format: 'json' });
      const parsed = JSON.parse(consoleLogs.join('\n'));
      expect(parsed[0].inventory.skills.map((s: { name: string }) => s.name)).toEqual(['pdf-tools']);
      expect(parsed[0].inventory.skillsDirs).toEqual([
        { path: join(root, 'skills'), exists: true },
        { path: join(root, 'missing'), exists: false },
      ]);
      expect(parsed[0].inventory.otherEntries).toHaveLength(1);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
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
      // status goes to stderr; stdout stays clean
      expect(consoleErrorLogs.join('\n')).toContain(`Report written to ${outPath}`);
      expect(stdout).not.toContain('"agent":');
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('writes <dir>/<hostname>.json for a local detect with --output-dir (and --silent)', async () => {
    vi.spyOn(adapterRegistry, 'detectAll').mockResolvedValue(mockInstallations);
    const { hostname } = await import('node:os');
    const { safeHostname } = await import('../transport/host-files.js');
    const dir = await mkdtemp(join(tmpdir(), 'vaso-detect-dir-'));
    try {
      await runDetect({ format: 'json', outputDir: dir, silent: true });
      const parsed = JSON.parse(await readFile(join(dir, `${safeHostname(hostname())}.json`), 'utf-8'));
      expect(parsed).toHaveLength(2);
      expect(consoleLogs.join('\n')).not.toContain('"agent":');
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
      // status goes to stderr; stdout stays clean
      expect(consoleErrorLogs.join('\n')).toContain(`Report written to ${outPath}`);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('rejects --silent without -o or --output-dir for local detect with exit 2', async () => {
    const consoleErrors: string[] = [];
    const origExitCode = process.exitCode;
    console.error = (...args: unknown[]) => { consoleErrors.push(args.map(String).join(' ')); };
    process.exitCode = undefined;
    try {
      await runDetect({ format: 'terminal', silent: true });
      expect(process.exitCode).toBe(2);
      expect(consoleErrors.some(l => l.includes('--silent requires'))).toBe(true);
    } finally {
      process.exitCode = origExitCode;
    }
  });

  it('rejects --save-snapshot without --host/--inventory with exit 2', async () => {
    const consoleErrors: string[] = [];
    const origExitCode = process.exitCode;
    console.error = (...args: unknown[]) => { consoleErrors.push(args.map(String).join(' ')); };
    process.exitCode = undefined;
    try {
      await runDetect({ format: 'terminal', saveSnapshot: '/tmp/snaps' });
      expect(process.exitCode).toBe(2);
      expect(consoleErrors.some(l => l.includes('--save-snapshot applies to remote scans only'))).toBe(true);
    } finally {
      process.exitCode = origExitCode;
    }
  });

  it('rejects a non-numeric --ssh-timeout with exit 2 before connecting', async () => {
    const consoleErrors: string[] = [];
    const origExitCode = process.exitCode;
    console.error = (...args: unknown[]) => { consoleErrors.push(args.map(String).join(' ')); };
    process.exitCode = undefined;
    try {
      await runDetect({ format: 'terminal', host: ['root@10.0.0.1'], sshTimeout: 'abc' });
      expect(process.exitCode).toBe(2);
      expect(consoleErrors.some(l => l.includes('--ssh-timeout'))).toBe(true);
    } finally {
      process.exitCode = origExitCode;
    }
  });

  it('rejects invalid --parallel / --ssh-timeout on a local detect too (exit 2)', async () => {
    const spy = vi.spyOn(adapterRegistry, 'detectAll').mockResolvedValue(mockInstallations);
    const origExitCode = process.exitCode;
    try {
      for (const bad of [{ parallel: '0' }, { sshTimeout: 'abc' }, { sshRetries: '-1' }]) {
        process.exitCode = undefined;
        await runDetect({ format: 'terminal', ...bad });
        expect(process.exitCode).toBe(2);
      }
      expect(spy).not.toHaveBeenCalled();
    } finally {
      process.exitCode = origExitCode;
    }
  });

  it('rejects -o + --output-dir together with exit 2', async () => {
    const consoleErrors: string[] = [];
    const origExitCode = process.exitCode;
    console.error = (...args: unknown[]) => { consoleErrors.push(args.map(String).join(' ')); };
    process.exitCode = undefined;
    try {
      await runDetect({ format: 'terminal', output: '/tmp/x', outputDir: '/tmp/y/' });
      expect(process.exitCode).toBe(2);
      expect(consoleErrors.some(l => l.includes('mutually exclusive'))).toBe(true);
    } finally {
      process.exitCode = origExitCode;
    }
  });

  it('verbose mode shows search paths', async () => {
    vi.spyOn(adapterRegistry, 'detectAll').mockResolvedValue([mockInstallations[0]]);
    vi.spyOn(adapterRegistry, 'getAdapters').mockReturnValue([
      {
        agent: 'openclaw',
        displayName: 'OpenClaw',
        async detect() { return []; },
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

  it('verbose mode on a snapshot lists adapters without the scanning machine\'s paths', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'vaso-detect-snap-'));
    try {
      const file = join(dir, 'host.json');
      await writeFile(file, JSON.stringify({
        version: 1, hostname: 'box', platform: 'linux', homedir: '/home/u', timestamp: 't',
        privilege: { uid: 1000, username: 'u', isRoot: false, sudoAvailable: false, escalated: false, scannedUsers: ['u'], skippedPaths: [] },
        files: {}, directories: {}, commandOutputs: {}, env: {},
      }));
      vi.spyOn(adapterRegistry, 'detectAll').mockResolvedValue([]);
      vi.spyOn(adapterRegistry, 'getAdapters').mockReturnValue([
        {
          agent: 'openclaw',
          displayName: 'OpenClaw',
          async detect() { return []; },
          getConfigPaths() { return ['/Users/scanner/.openclaw/openclaw.json']; },
          getSkillsDir() { return undefined; },
          getGatewayInfo() { return undefined; },
        },
      ]);

      await runDetect({ format: 'terminal', verbose: true, snapshot: file });

      const output = consoleLogs.join('\n');
      expect(output).toContain('search paths are listed for local detection only');
      expect(output).toContain('OpenClaw');
      expect(output).not.toContain('/Users/scanner/.openclaw/openclaw.json');
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('--silent on a snapshot prints no progress line', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'vaso-detect-snap-'));
    try {
      const file = join(dir, 'host.json');
      await writeFile(file, JSON.stringify({
        version: 1, hostname: 'box', platform: 'linux', homedir: '/home/u', timestamp: 't',
        privilege: { uid: 1000, username: 'u', isRoot: false, sudoAvailable: false, escalated: false, scannedUsers: ['u'], skippedPaths: [] },
        files: {}, directories: {}, commandOutputs: {}, env: {},
      }));
      vi.spyOn(adapterRegistry, 'detectAll').mockResolvedValue([]);
      await runDetect({ format: 'json', snapshot: file, silent: true, output: join(dir, 'out.json') });
      expect(consoleErrorLogs.some(l => l.includes('Detecting agents from snapshot'))).toBe(false);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
