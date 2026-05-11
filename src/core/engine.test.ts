import { describe, it, expect } from 'vitest';
import { ScanEngine } from './engine.js';
import { CheckRegistry } from './check-registry.js';
import { AdapterRegistry } from '../adapters/registry.js';
import type { CheckModule, ScanContext, CheckResult, AgentInstallation } from './types.js';
import type { AgentAdapter } from '../adapters/adapter.js';
import type { FSProvider } from './fs-provider.js';

const mockInstallation: AgentInstallation = {
  agent: 'openclaw',
  installDir: '/tmp/test-openclaw',
  configFiles: [],
};

const mockAdapter: AgentAdapter = {
  agent: 'openclaw',
  displayName: 'OpenClaw',
  async detect() { return [mockInstallation]; },
  getConfigPaths() { return []; },
  getSkillsDir() { return undefined; },
  getGatewayInfo() { return undefined; },
};

const failingAdapter: AgentAdapter = {
  agent: 'codex',
  displayName: 'Codex',
  async detect() { throw new Error('cannot read config'); },
  getConfigPaths() { return []; },
  getSkillsDir() { return undefined; },
  getGatewayInfo() { return undefined; },
};

function mockCheck(id: string, passed: boolean, severity: 'critical' | 'warning' | 'info' = 'warning'): CheckModule {
  return {
    id,
    name: `Check ${id}`,
    category: 'config',
    severity,
    description: `Mock check ${id}`,
    async run(_ctx: ScanContext): Promise<CheckResult> {
      return {
        id,
        name: `Check ${id}`,
        category: 'config',
        severity,
        passed,
        message: passed ? 'OK' : 'Failed',
      };
    },
  };
}

function mockFs(platform: NodeJS.Platform): FSProvider {
  return {
    platform,
    async readFile() { throw new Error('not implemented'); },
    async readBytes() { return new Uint8Array(); },
    async readdir() { return []; },
    async readdirEntries() { return []; },
    async access() { return false; },
    async stat() {
      throw new Error('not implemented');
    },
    async realpath(path: string) { return path; },
    async exec() { return { stdout: '', stderr: '', exitCode: 0 }; },
    execSync() { return ''; },
    getEnv() { return undefined; },
    homedir() { return '/home/test'; },
  };
}

describe('ScanEngine', () => {
  it('runs end-to-end with mock adapter and checks', async () => {
    const adapters = new AdapterRegistry();
    adapters.register(mockAdapter);

    const checks = new CheckRegistry();
    checks.register(mockCheck('CFG-001', true));
    checks.register(mockCheck('CFG-002', false, 'critical'));
    checks.register(mockCheck('CFG-003', false, 'warning'));

    const engine = new ScanEngine(adapters, checks);
    const result = await engine.scan({});

    console.log(`[ScanEngine] end-to-end → agents: ${result.agents.length}, agent: ${result.agents[0].agent}`);
    console.log(`[ScanEngine] results: ${result.agents[0].results.map(r => `${r.id}:${r.passed ? 'PASS' : 'FAIL'}(${r.severity})`).join(', ')}`);
    console.log(`[ScanEngine] score: ${result.agents[0].score}, grade: ${result.agents[0].grade}`);
    console.log(`[ScanEngine] summary:`, JSON.stringify(result.summary));

    expect(result.agents).toHaveLength(1);
    expect(result.agents[0].agent).toBe('openclaw');
    expect(result.agents[0].results).toHaveLength(3);
    expect(result.agents[0].score).toBe(83); // 100 - 12 - 5
    expect(result.agents[0].grade).toBe('B');
    expect(result.summary.critical).toBe(1);
    expect(result.summary.warning).toBe(1);
    expect(result.summary.passed).toBe(1);
  });

  it('returns empty result when no agents detected', async () => {
    const adapters = new AdapterRegistry();
    const checks = new CheckRegistry();

    const engine = new ScanEngine(adapters, checks);
    const result = await engine.scan({});

    console.log(`[ScanEngine] no agents → agents: ${result.agents.length}, totalScore: ${result.totalScore}, totalGrade: ${result.totalGrade}`);

    expect(result.agents).toHaveLength(0);
    expect(result.totalScore).toBe(100);
    expect(result.totalGrade).toBe('A');
  });

  it('filters by agent name', async () => {
    const adapters = new AdapterRegistry();
    adapters.register(mockAdapter);

    const checks = new CheckRegistry();
    checks.register(mockCheck('CFG-001', true));

    const engine = new ScanEngine(adapters, checks);

    // Filter for non-existent agent
    const result = await engine.scan({ agentFilter: 'nanoclaw' });
    console.log(`[ScanEngine] filter nanoclaw → agents found: ${result.agents.length}`);
    expect(result.agents).toHaveLength(0);

    // Filter for existing agent
    const result2 = await engine.scan({ agentFilter: 'openclaw' });
    console.log(`[ScanEngine] filter openclaw → agents found: ${result2.agents.length}`);
    expect(result2.agents).toHaveLength(1);
  });

  it('reports check failures as warning findings', async () => {
    const adapters = new AdapterRegistry();
    adapters.register(mockAdapter);

    const checks = new CheckRegistry();
    checks.register({
      id: 'FAIL-001',
      name: 'Failing Check',
      category: 'config',
      severity: 'critical',
      description: 'Always fails',
      async run() { throw new Error('boom'); },
    });
    checks.register(mockCheck('CFG-001', true));

    const engine = new ScanEngine(adapters, checks);
    const result = await engine.scan({});

    console.log(`[ScanEngine] graceful failure → results count: ${result.agents[0].results.length}, results: ${result.agents[0].results.map(r => `${r.id}:${r.passed}`).join(', ')}`);

    expect(result.agents[0].results).toHaveLength(2);
    const failed = result.agents[0].results.find(r => r.id === 'FAIL-001');
    expect(failed?.passed).toBe(false);
    expect(failed?.severity).toBe('warning');
    expect(failed?.message).toContain('boom');
    expect(result.summary.warning).toBe(1);
  });

  it('uses the scanned filesystem platform for applicable checks', async () => {
    const adapters = new AdapterRegistry();
    adapters.register(mockAdapter);

    const checks = new CheckRegistry();
    checks.register({
      ...mockCheck('LINUX-001', true),
      supportedPlatforms: ['linux'],
    });
    checks.register({
      ...mockCheck('DARWIN-001', true),
      supportedPlatforms: ['darwin'],
    });

    const engine = new ScanEngine(adapters, checks, mockFs('linux'));
    const result = await engine.scan({});

    expect(result.agents[0].results.map(r => r.id)).toEqual(['LINUX-001']);
  });

  it('populates ctx.skillFiles via the engine FS provider when skillsDir is set', async () => {
    const installation: AgentInstallation = {
      agent: 'openclaw',
      installDir: '/snap/openclaw',
      skillsDir: '/snap/openclaw/skills',
      configFiles: [],
    };

    const adapter: AgentAdapter = {
      agent: 'openclaw',
      displayName: 'OpenClaw',
      async detect() { return [installation]; },
      getConfigPaths() { return []; },
      getSkillsDir() { return '/snap/openclaw/skills'; },
      getGatewayInfo() { return undefined; },
    };

    let readdirCalledWith: string | undefined;
    const fs: FSProvider = {
      ...mockFs('linux'),
      async readdirEntries(dir: string) {
        readdirCalledWith = dir;
        return [
          { name: 'a.py', isFile: true, isDirectory: false, parentPath: dir },
          { name: 'b.js', isFile: true, isDirectory: false, parentPath: dir },
          { name: 'c.txt', isFile: true, isDirectory: false, parentPath: dir },
        ];
      },
    };

    let captured: string[] | undefined;
    const recorder: CheckModule = {
      id: 'REC-001',
      name: 'Recorder',
      category: 'skills',
      severity: 'info',
      description: 'Records ctx.skillFiles',
      async run(ctx) {
        captured = ctx.skillFiles;
        return {
          id: 'REC-001',
          name: 'Recorder',
          category: 'skills',
          severity: 'info',
          passed: true,
          message: 'recorded',
        };
      },
    };

    const adapters = new AdapterRegistry();
    adapters.register(adapter);
    const checks = new CheckRegistry();
    checks.register(recorder);

    const engine = new ScanEngine(adapters, checks, fs);
    await engine.scan({});

    expect(readdirCalledWith).toBe('/snap/openclaw/skills');
    expect(captured).toEqual([
      '/snap/openclaw/skills/a.py',
      '/snap/openclaw/skills/b.js',
    ]);
  });

  it('aggregates ctx.skillFiles across every dir in installation.skillsDirs', async () => {
    // OpenClaw per-agent installations declare both the shared and the per-agent
    // skills locations via skillsDirs. ctx.skillFiles must include files from
    // every entry so skill / IOC checks see the full surface, not just the
    // last dir.
    const installation: AgentInstallation = {
      agent: 'openclaw',
      installDir: '/snap/openclaw/agents/researcher',
      skillsDir: '/snap/openclaw/agents/researcher/skills', // per-agent
      skillsDirs: [
        '/snap/openclaw/skills',                            // shared
        '/snap/openclaw/agents/researcher/skills',          // per-agent
      ],
      configFiles: [],
    };

    const adapter: AgentAdapter = {
      agent: 'openclaw',
      displayName: 'OpenClaw',
      async detect() { return [installation]; },
      getConfigPaths() { return []; },
      getSkillsDir() { return '/snap/openclaw/agents/researcher/skills'; },
      getGatewayInfo() { return undefined; },
    };

    const filesByDir: Record<string, string[]> = {
      '/snap/openclaw/skills': ['shared.js', 'common.py'],
      '/snap/openclaw/agents/researcher/skills': ['agent-specific.ts'],
    };

    const fs: FSProvider = {
      ...mockFs('linux'),
      async readdirEntries(dir: string) {
        const names = filesByDir[dir] ?? [];
        return names.map(name => ({ name, isFile: true, isDirectory: false, parentPath: dir }));
      },
    };

    let captured: string[] | undefined;
    const recorder: CheckModule = {
      id: 'REC-003',
      name: 'Recorder',
      category: 'skills',
      severity: 'info',
      description: 'Records ctx.skillFiles',
      async run(ctx) {
        captured = ctx.skillFiles;
        return {
          id: 'REC-003',
          name: 'Recorder',
          category: 'skills',
          severity: 'info',
          passed: true,
          message: 'recorded',
        };
      },
    };

    const adapters = new AdapterRegistry();
    adapters.register(adapter);
    const checks = new CheckRegistry();
    checks.register(recorder);

    const engine = new ScanEngine(adapters, checks, fs);
    await engine.scan({});

    expect(captured).toEqual([
      '/snap/openclaw/skills/shared.js',
      '/snap/openclaw/skills/common.py',
      '/snap/openclaw/agents/researcher/skills/agent-specific.ts',
    ]);
  });

  it('leaves ctx.skillFiles undefined when installation has no skillsDir', async () => {
    let captured: string[] | undefined | 'unset' = 'unset';
    const recorder: CheckModule = {
      id: 'REC-002',
      name: 'Recorder',
      category: 'skills',
      severity: 'info',
      description: 'Records ctx.skillFiles',
      async run(ctx) {
        captured = ctx.skillFiles;
        return {
          id: 'REC-002',
          name: 'Recorder',
          category: 'skills',
          severity: 'info',
          passed: true,
          message: 'recorded',
        };
      },
    };

    const adapters = new AdapterRegistry();
    adapters.register(mockAdapter);
    const checks = new CheckRegistry();
    checks.register(recorder);

    const engine = new ScanEngine(adapters, checks);
    await engine.scan({});

    expect(captured).toBeUndefined();
  });

  it('reports adapter detection failures as warning findings', async () => {
    const adapters = new AdapterRegistry();
    adapters.register(mockAdapter);
    adapters.register(failingAdapter);

    const checks = new CheckRegistry();
    checks.register(mockCheck('CFG-001', true));

    const engine = new ScanEngine(adapters, checks);
    const result = await engine.scan({});

    const codex = result.agents.find(a => a.agent === 'codex');
    expect(codex).toBeDefined();
    expect(codex?.results).toHaveLength(1);
    expect(codex?.results[0]).toMatchObject({
      id: 'ADAPTER-DETECT',
      passed: false,
      severity: 'warning',
    });
    expect(codex?.results[0].message).toContain('cannot read config');
  });
});
