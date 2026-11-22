import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { join } from 'node:path';
import { mkdtempSync, mkdirSync, writeFileSync, chmodSync, rmSync, statSync } from 'node:fs';
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
  it('exports 7 checks', () => {
    expect(openclawChecks).toHaveLength(7);
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
  const main = (data: Record<string, unknown>) => [makeConfig('/home/test/.openclaw/openclaw.json', data)];

  it('passes when no agent entry overrides the defaults', async () => {
    expect((await check.run(makeCtx({}))).passed).toBe(true);
    expect((await check.run(makeCtx({ configs: main({ agents: { defaults: { sandbox: { mode: 'all' } } } }) }))).passed).toBe(true);
  });

  it('flags an agents.entries.<id> entry that turns the default sandbox off', async () => {
    const configs = main({ agents: { defaults: { sandbox: { mode: 'all' } }, entries: { worker: { sandbox: { mode: 'off' } } } } });
    const result = await check.run(makeCtx({ configs }));
    expect(result.passed).toBe(false);
    expect(result.severity).toBe('critical');
    expect(result.evidence?.[0].detail).toBe('agents.entries.worker: Sandbox disabled (base had sandbox enabled)');
  });

  it('flags an entry that drops exec approval (agents.list[] form too)', async () => {
    const configs = main({ tools: { exec: { mode: 'ask' } }, agents: { list: [{ id: 'ops', tools: { exec: { mode: 'full' } } }] } });
    const result = await check.run(makeCtx({ configs }));
    expect(result.passed).toBe(false);
    expect(result.evidence?.[0].detail).toMatch(/^agents\.entries\.ops: Tool approval no longer required/);
  });

  it('passes an entry that keeps or tightens the defaults', async () => {
    const configs = main({ agents: { defaults: { sandbox: { mode: 'non-main' } }, entries: { a: { sandbox: { mode: 'all' } }, b: { tools: { exec: { mode: 'ask' } } } } } });
    expect((await check.run(makeCtx({ configs }))).passed).toBe(true);
  });
});

describe('OC-003: Legacy Bot Config Directory', () => {
  const check = openclawChecks.find(c => c.id === 'OC-003')!;

  it('passes for .openclaw installation', async () => {
    const result = await check.run(makeCtx({ installDir: '/home/test/.openclaw' }));
    expect(result.passed).toBe(true);
  });

  it('flags OpenClaw running from ~/.clawdbot (no config in ~/.openclaw) as a warning', async () => {
    const fs = makeMemFs({ exists: new Set(['/home/test/.openclaw']) });
    const result = await check.run(makeCtx({ installDir: '/home/test/.clawdbot', fs }));
    expect(result.passed).toBe(false);
    expect(result.severity).toBe('warning');
    expect(result.evidence?.[0].detail).toMatch(/runs from the pre-rename \.clawdbot/);
  });

  it('reports leftover .clawdbot / .moltbot next to a live .openclaw as info — OpenClaw does not read them', async () => {
    const fs = makeMemFs({ exists: new Set(['/home/test/.clawdbot', '/home/test/.moltbot']) });
    const result = await check.run(makeCtx({ installDir: '/home/test/.openclaw', fs }));
    expect(result.passed).toBe(false);
    expect(result.severity).toBe('info');
    expect(result.evidence?.map(e => e.file)).toEqual(['/home/test/.clawdbot', '/home/test/.moltbot']);
    expect(result.evidence?.[1].detail).toMatch(/no longer reads it/);
  });

  it('looks for leftovers in OPENCLAW_HOME when OPENCLAW_STATE_DIR moved the state dir', async () => {
    const fs = makeMemFs({ exists: new Set(['/srv/oc/.moltbot']), env: { OPENCLAW_HOME: '/srv/oc', OPENCLAW_STATE_DIR: '/var/lib/oc' } });
    const result = await check.run(makeCtx({ installDir: '/var/lib/oc', fs }));
    expect(result.evidence?.map(e => e.file)).toEqual(['/srv/oc/.moltbot']);
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

describe('OC-001/OC-005 posture: OpenClaw 2026.x keys', () => {
  const check = openclawChecks.find(c => c.id === 'OC-001')!;

  it('reads agents.defaults.sandbox.mode and tools.exec against an entry\'s overrides', async () => {
    const configs = [makeConfig('/home/test/.openclaw/openclaw.json', {
      agents: { defaults: { sandbox: { mode: 'all' } }, entries: { ops: { sandbox: { mode: 'off' }, tools: { exec: { mode: 'full' } } } } },
      tools: { exec: { mode: 'ask' } },
    })];
    const result = await check.run(makeCtx({ configs }));
    const details = (result.evidence ?? []).map(e => e.detail).join('\n');
    expect(details).toMatch(/Sandbox disabled/);
    expect(details).toMatch(/approval no longer required/);
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

  /** 2026.x store layout under a state dir, every file at `mode`. */
  function writeStores(mode: number): string[] {
    const files = [
      'state/openclaw.sqlite',
      'state/openclaw.sqlite-wal',
      'agents/main/agent/openclaw-agent.sqlite',
      'agents/main/agent/auth-profiles.json',
      'credentials/oauth.json',
      'credentials/whatsapp/a1/creds.json',
      'identity/device.json',
    ];
    for (const f of files) {
      mkdirSync(join(tmpRoot, f, '..'), { recursive: true });
      writeFileSync(join(tmpRoot, f), 'x');
      chmodSync(join(tmpRoot, f), mode);
    }
    return files.map(f => join(tmpRoot, f));
  }

  it('flags the 2026.x credential and state stores readable by others', async () => {
    const files = writeStores(0o644);
    // agents/<id>/sessions is conversation data, not a store this check owns
    mkdirSync(join(tmpRoot, 'agents/main/sessions'), { recursive: true });
    writeFileSync(join(tmpRoot, 'agents/main/sessions/s.jsonl'), '');
    const result = await check.run(makeCtx({ installDir: tmpRoot, fs: new LocalFSProvider() }));
    expect(result.passed).toBe(false);
    expect(result.evidence?.map(e => e.file).sort()).toEqual([...files].sort());
  });

  it('passes the same stores when they are owner-only', async () => {
    writeStores(0o600);
    const result = await check.run(makeCtx({ installDir: tmpRoot, fs: new LocalFSProvider() }));
    expect(result.passed).toBe(true);
  });

  it('checks a file secrets provider named in the config', async () => {
    const secrets = join(tmpRoot, 'vault.json');
    writeFileSync(secrets, '{}');
    chmodSync(secrets, 0o644);
    const configs = [makeConfig(join(tmpRoot, 'openclaw.json'), { secrets: { providers: { filemain: { source: 'file', path: secrets }, env: { source: 'env' } } } })];
    const result = await check.run(makeCtx({ installDir: tmpRoot, configs, fs: new LocalFSProvider() }));
    expect(result.evidence?.map(e => e.file)).toEqual([secrets]);
  });

  it('fix removes group/other access from every exposed store', async () => {
    const files = writeStores(0o644);
    const ctx = makeCtx({ installDir: tmpRoot, fs: new LocalFSProvider() });
    const fixed = await check.fix!(ctx);
    expect(fixed.applied).toBe(true);
    for (const f of files) expect(statSync(f).mode & 0o077).toBe(0);
    expect((await check.run(ctx)).passed).toBe(true);
  });
});

describe('OC-007: /etc/openclaw Writable by Non-Root (retired)', () => {
  const check = openclawChecks.find(c => c.id === 'OC-007')!;

  it('passes when /etc/openclaw does not exist', async () => {
    const fs = makeMemFs({ exists: new Set() });
    const result = await check.run(makeCtx({ fs }));
    expect(result.passed).toBe(true);
  });

  // No OpenClaw release reads /etc/openclaw, so a writable one hijacks nothing
  it('passes for a world-writable /etc/openclaw and config file, saying OpenClaw never reads it', async () => {
    const fs = makeMemFs({
      exists: new Set(['/etc/openclaw', '/etc/openclaw/openclaw.json']),
      modes: { '/etc/openclaw': 0o777, '/etc/openclaw/openclaw.json': 0o666 },
    });
    const result = await check.run(makeCtx({ fs }));
    expect(result.passed).toBe(true);
    expect(result.evidence).toBeUndefined();
    expect(result.message).toMatch(/does not read \/etc\/openclaw/);
  });
});
