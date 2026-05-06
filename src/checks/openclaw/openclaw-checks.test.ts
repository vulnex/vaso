import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { join } from 'node:path';
import { mkdtempSync, mkdirSync, writeFileSync, chmodSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import type { ScanContext, ParsedConfig, AgentInstallation } from '../../core/types.js';
import type { FSProvider } from '../../core/fs-provider.js';
import { LocalFSProvider } from '../../core/local-fs-provider.js';
import { openclawChecks } from './index.js';

function makeConfig(filePath: string, data: Record<string, unknown>, format: ParsedConfig['format'] = 'json'): ParsedConfig {
  return { raw: JSON.stringify(data), format, filePath, data };
}

function makeMemFs(opts: {
  exists?: Set<string>;
  modes?: Record<string, number>;
  homedir?: string;
  platform?: NodeJS.Platform;
  env?: Record<string, string>;
} = {}): FSProvider {
  const exists = opts.exists ?? new Set<string>();
  const modes = opts.modes ?? {};
  const env = opts.env ?? {};
  return {
    readFile: vi.fn(async (p: string) => {
      if (!exists.has(p)) throw new Error('ENOENT');
      return '';
    }),
    readdir: vi.fn(async () => []),
    readdirEntries: vi.fn(async () => []),
    access: vi.fn(async (p: string) => exists.has(p)),
    stat: vi.fn(async (p: string) => {
      if (!exists.has(p)) throw new Error('ENOENT');
      const mode = modes[p] ?? 0o600;
      return { mode, isFile: () => true, isDirectory: () => false };
    }),
    realpath: vi.fn(async (p: string) => p),
    exec: vi.fn(),
    execSync: vi.fn(),
    getEnv: (key: string) => env[key],
    homedir: () => opts.homedir ?? '/home/test',
    platform: opts.platform ?? 'linux',
  } as FSProvider;
}

function makeCtx(opts: {
  configs?: ParsedConfig[];
  installDir?: string;
  agentName?: string;
  profile?: string;
  fs?: FSProvider;
  platform?: NodeJS.Platform;
} = {}): ScanContext {
  const installation: AgentInstallation = {
    agent: 'openclaw',
    installDir: opts.installDir ?? '/home/test/.openclaw',
    configFiles: opts.configs ?? [],
    agentName: opts.agentName,
    profile: opts.profile,
  };
  return {
    installation,
    configs: opts.configs ?? [],
    platform: opts.platform ?? 'linux',
    fs: opts.fs ?? makeMemFs(),
  };
}

describe('OpenClaw checks', () => {
  it('exports 6 checks', () => {
    expect(openclawChecks).toHaveLength(6);
  });

  it('all checks have openclaw category and supportedAgents=["openclaw"]', () => {
    for (const check of openclawChecks) {
      expect(check.category).toBe('openclaw');
      expect(check.supportedAgents).toEqual(['openclaw']);
    }
  });

  it('all check IDs match OC-0NN', () => {
    for (const check of openclawChecks) {
      expect(check.id).toMatch(/^OC-0\d{2}$/);
    }
  });
});

describe('OC-001: Sub-Agent Config Security Downgrade', () => {
  const check = openclawChecks.find(c => c.id === 'OC-001')!;

  it('skips when not a sub-agent', async () => {
    const result = await check.run(makeCtx({}));
    expect(result.passed).toBe(true);
  });

  it('flags when sub-agent re-binds gateway from loopback to 0.0.0.0', async () => {
    const installDir = '/home/test/.openclaw/agents/foo';
    const configs = [
      makeConfig('/home/test/.openclaw/openclaw.json', { gateway: { host: '127.0.0.1', port: 8080 } }),
      makeConfig(join(installDir, 'agent.json'), { gateway: { host: '0.0.0.0' } }),
    ];
    const result = await check.run(makeCtx({ configs, installDir, agentName: 'foo' }));
    expect(result.passed).toBe(false);
    expect(result.severity).toBe('critical');
    expect(result.evidence?.[0].detail).toMatch(/Gateway re-bound/);
  });

  it('flags when sub-agent disables sandbox', async () => {
    const installDir = '/home/test/.openclaw/agents/bar';
    const configs = [
      makeConfig('/home/test/.openclaw/openclaw.json', { sandbox: { enabled: true } }),
      makeConfig(join(installDir, 'agent.json'), { sandbox: { enabled: false } }),
    ];
    const result = await check.run(makeCtx({ configs, installDir, agentName: 'bar' }));
    expect(result.passed).toBe(false);
    expect(result.evidence?.[0].detail).toMatch(/Sandbox disabled/);
  });

  it('passes when sub-agent matches global posture', async () => {
    const installDir = '/home/test/.openclaw/agents/baz';
    const configs = [
      makeConfig('/home/test/.openclaw/openclaw.json', { gateway: { host: '127.0.0.1', tls: true } }),
      makeConfig(join(installDir, 'agent.json'), { tools: { allow: ['fetch'] } }),
    ];
    const result = await check.run(makeCtx({ configs, installDir, agentName: 'baz' }));
    expect(result.passed).toBe(true);
  });

  it('flags auth mode downgrade (oauth -> none)', async () => {
    const installDir = '/home/test/.openclaw/agents/qux';
    const configs = [
      makeConfig('/home/test/.openclaw/openclaw.json', { gateway: { auth: { mode: 'oauth2' } } }),
      makeConfig(join(installDir, 'agent.json'), { gateway: { auth: { mode: 'none' } } }),
    ];
    const result = await check.run(makeCtx({ configs, installDir, agentName: 'qux' }));
    expect(result.passed).toBe(false);
    expect(result.evidence?.[0].detail).toMatch(/Auth mode downgraded/);
  });
});

describe('OC-003: Legacy Bot Config Directory', () => {
  const check = openclawChecks.find(c => c.id === 'OC-003')!;

  it('passes for .openclaw installation', async () => {
    const result = await check.run(makeCtx({ installDir: '/home/test/.openclaw' }));
    expect(result.passed).toBe(true);
  });

  it('flags .clawdbot installation', async () => {
    const fs = makeMemFs({ exists: new Set(['/home/test/.openclaw']) });
    const result = await check.run(makeCtx({ installDir: '/home/test/.clawdbot', fs }));
    expect(result.passed).toBe(false);
    expect(result.evidence?.[0].detail).toMatch(/alongside \.openclaw/);
  });

  it('flags .moltbot installation even without .openclaw sibling', async () => {
    const fs = makeMemFs({ exists: new Set() });
    const result = await check.run(makeCtx({ installDir: '/home/test/.moltbot', fs }));
    expect(result.passed).toBe(false);
    expect(result.evidence?.[0].detail).toMatch(/without a current \.openclaw/);
  });

  it('skips for sub-agent installations', async () => {
    const result = await check.run(makeCtx({
      installDir: '/home/test/.clawdbot/agents/foo',
      agentName: 'foo',
    }));
    expect(result.passed).toBe(true);
  });
});

describe('OC-004: OPENCLAW_HOME Redirect', () => {
  const check = openclawChecks.find(c => c.id === 'OC-004')!;

  it('passes when OPENCLAW_HOME is unset', async () => {
    const result = await check.run(makeCtx({ installDir: '/home/test/.openclaw' }));
    expect(result.passed).toBe(true);
  });

  it('passes when OPENCLAW_HOME points inside the user home', async () => {
    const result = await check.run(makeCtx({
      installDir: '/home/test/custom-openclaw',
      fs: makeMemFs({ env: { OPENCLAW_HOME: '/home/test/custom-openclaw' } }),
    }));
    expect(result.passed).toBe(true);
  });

  it('flags world-writable redirect with critical severity', async () => {
    const result = await check.run(makeCtx({
      installDir: '/tmp/openclaw-shadow',
      fs: makeMemFs({ env: { OPENCLAW_HOME: '/tmp/openclaw-shadow' } }),
    }));
    expect(result.passed).toBe(false);
    expect(result.severity).toBe('critical');
    expect(result.evidence?.[0].detail).toMatch(/world-writable/);
  });

  it('flags non-home, non-tmp redirect with warning severity', async () => {
    const result = await check.run(makeCtx({
      installDir: '/opt/agent-config',
      fs: makeMemFs({ env: { OPENCLAW_HOME: '/opt/agent-config' } }),
    }));
    expect(result.passed).toBe(false);
    expect(result.severity).toBe('warning');
  });

  it('does not double-fire on installations not driven by OPENCLAW_HOME', async () => {
    const result = await check.run(makeCtx({
      installDir: '/home/test/.openclaw',
      fs: makeMemFs({ env: { OPENCLAW_HOME: '/tmp/openclaw-shadow' } }),
    }));
    expect(result.passed).toBe(true);
  });

  it('reads OPENCLAW_HOME from ctx.fs.getEnv (not process.env), so snapshot scans work', async () => {
    const originalProcessValue = process.env.OPENCLAW_HOME;
    delete process.env.OPENCLAW_HOME;
    try {
      const result = await check.run(makeCtx({
        installDir: '/dev/shm/snapshot-shadow',
        fs: makeMemFs({ env: { OPENCLAW_HOME: '/dev/shm/snapshot-shadow' } }),
      }));
      expect(result.passed).toBe(false);
      expect(result.severity).toBe('critical');
    } finally {
      if (originalProcessValue !== undefined) process.env.OPENCLAW_HOME = originalProcessValue;
    }
  });
});

describe('OC-005: Profile Config Weaker Than Default', () => {
  const check = openclawChecks.find(c => c.id === 'OC-005')!;
  let tmpRoot: string;

  beforeEach(() => {
    tmpRoot = mkdtempSync(join(tmpdir(), 'vaso-oc005-'));
  });

  afterEach(() => {
    rmSync(tmpRoot, { recursive: true, force: true });
  });

  it('passes when no profile is set', async () => {
    const result = await check.run(makeCtx({ installDir: '/home/test/.openclaw' }));
    expect(result.passed).toBe(true);
  });

  it('flags profile dir with weaker posture than default', async () => {
    const defaultDir = join(tmpRoot, '.openclaw');
    const profileDir = join(tmpRoot, '.openclaw-staging');
    mkdirSync(defaultDir);
    mkdirSync(profileDir);
    writeFileSync(join(defaultDir, 'openclaw.json'), JSON.stringify({
      gateway: { host: '127.0.0.1', tls: true },
    }));

    const profileConfig = makeConfig(join(profileDir, 'openclaw.json'), {
      gateway: { host: '0.0.0.0', tls: false },
    });

    const result = await check.run(makeCtx({
      configs: [profileConfig],
      installDir: profileDir,
      profile: 'staging',
      fs: new LocalFSProvider(),
    }));
    expect(result.passed).toBe(false);
    expect(result.evidence?.length).toBeGreaterThanOrEqual(2);
  });

  it('passes when profile matches default posture', async () => {
    const defaultDir = join(tmpRoot, '.openclaw');
    const profileDir = join(tmpRoot, '.openclaw-staging');
    mkdirSync(defaultDir);
    mkdirSync(profileDir);
    writeFileSync(join(defaultDir, 'openclaw.json'), JSON.stringify({
      gateway: { host: '127.0.0.1', tls: true },
    }));

    const profileConfig = makeConfig(join(profileDir, 'openclaw.json'), {
      gateway: { host: '127.0.0.1', tls: true },
    });

    const result = await check.run(makeCtx({
      configs: [profileConfig],
      installDir: profileDir,
      profile: 'staging',
      fs: new LocalFSProvider(),
    }));
    expect(result.passed).toBe(true);
  });
});

describe('OC-006: Memory File Permissions', () => {
  const check = openclawChecks.find(c => c.id === 'OC-006')!;
  let tmpRoot: string;

  beforeEach(() => {
    tmpRoot = mkdtempSync(join(tmpdir(), 'vaso-oc006-'));
  });

  afterEach(() => {
    rmSync(tmpRoot, { recursive: true, force: true });
  });

  it('passes when memory files are 0600', async () => {
    writeFileSync(join(tmpRoot, 'memory.json'), '{}');
    chmodSync(join(tmpRoot, 'memory.json'), 0o600);
    const result = await check.run(makeCtx({ installDir: tmpRoot, fs: new LocalFSProvider() }));
    expect(result.passed).toBe(true);
  });

  it('flags memory.json with 0644', async () => {
    writeFileSync(join(tmpRoot, 'memory.json'), '{}');
    chmodSync(join(tmpRoot, 'memory.json'), 0o644);
    const result = await check.run(makeCtx({ installDir: tmpRoot, fs: new LocalFSProvider() }));
    expect(result.passed).toBe(false);
    expect(result.evidence?.[0].detail).toMatch(/644/);
  });

  it('passes when memory files do not exist', async () => {
    const result = await check.run(makeCtx({ installDir: tmpRoot, fs: new LocalFSProvider() }));
    expect(result.passed).toBe(true);
  });
});

describe('OC-007: /etc/openclaw Writable by Non-Root', () => {
  const check = openclawChecks.find(c => c.id === 'OC-007')!;

  it('passes when /etc/openclaw does not exist', async () => {
    const fs = makeMemFs({ exists: new Set() });
    const result = await check.run(makeCtx({ fs }));
    expect(result.passed).toBe(true);
  });

  it('flags world-writable /etc/openclaw directory', async () => {
    const fs = makeMemFs({
      exists: new Set(['/etc/openclaw']),
      modes: { '/etc/openclaw': 0o777 },
    });
    const result = await check.run(makeCtx({ fs }));
    expect(result.passed).toBe(false);
    expect(result.severity).toBe('critical');
  });

  it('passes when /etc/openclaw is 0755', async () => {
    const fs = makeMemFs({
      exists: new Set(['/etc/openclaw']),
      modes: { '/etc/openclaw': 0o755 },
    });
    const result = await check.run(makeCtx({ fs }));
    expect(result.passed).toBe(true);
  });

  it('flags world-writable config file under /etc/openclaw', async () => {
    const fs = makeMemFs({
      exists: new Set(['/etc/openclaw', '/etc/openclaw/openclaw.json']),
      modes: {
        '/etc/openclaw': 0o755,
        '/etc/openclaw/openclaw.json': 0o666,
      },
    });
    const result = await check.run(makeCtx({ fs }));
    expect(result.passed).toBe(false);
    expect(result.evidence?.[0].file).toContain('openclaw.json');
  });
});
