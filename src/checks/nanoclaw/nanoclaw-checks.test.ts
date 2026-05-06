import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { join } from 'node:path';
import { mkdtempSync, mkdirSync, writeFileSync, chmodSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import type { ScanContext, ParsedConfig, AgentInstallation } from '../../core/types.js';
import type { FSProvider } from '../../core/fs-provider.js';
import { LocalFSProvider } from '../../core/local-fs-provider.js';
import { nanoclawChecks } from './index.js';

function makeConfig(filePath: string, data: Record<string, unknown>, format: ParsedConfig['format'] = 'json'): ParsedConfig {
  return { raw: JSON.stringify(data), format, filePath, data };
}

function makeMemFs(opts: {
  exists?: Set<string>;
  modes?: Record<string, number>;
  homedir?: string;
  env?: Record<string, string>;
} = {}): FSProvider {
  const exists = opts.exists ?? new Set<string>();
  const modes = opts.modes ?? {};
  const env = opts.env ?? {};
  return {
    readFile: vi.fn(async () => ''),
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
    platform: 'linux',
  } as FSProvider;
}

function makeCtx(opts: {
  configs?: ParsedConfig[];
  installDir?: string;
  skillsDir?: string;
  fs?: FSProvider;
} = {}): ScanContext {
  const installation: AgentInstallation = {
    agent: 'nanoclaw',
    installDir: opts.installDir ?? '/home/test/.config/nanoclaw',
    configFiles: opts.configs ?? [],
    skillsDir: opts.skillsDir,
  };
  return {
    installation,
    configs: opts.configs ?? [],
    platform: 'linux',
    fs: opts.fs ?? makeMemFs(),
  };
}

describe('NanoClaw checks', () => {
  it('exports 5 checks', () => {
    expect(nanoclawChecks).toHaveLength(5);
  });

  it('all checks have nanoclaw category and supportedAgents=["nanoclaw"]', () => {
    for (const check of nanoclawChecks) {
      expect(check.category).toBe('nanoclaw');
      expect(check.supportedAgents).toEqual(['nanoclaw']);
    }
  });

  it('all check IDs match NC-0NN', () => {
    for (const check of nanoclawChecks) {
      expect(check.id).toMatch(/^NC-0\d{2}$/);
    }
  });
});

describe('NC-001: Overbroad Mount Allowlist', () => {
  const check = nanoclawChecks.find(c => c.id === 'NC-001')!;

  it('flags root path "/"', async () => {
    const config = makeConfig('/h/.config/nanoclaw/mount-allowlist.json', { allowedPaths: ['/'] });
    const result = await check.run(makeCtx({ configs: [config] }));
    expect(result.passed).toBe(false);
    expect(result.severity).toBe('critical');
  });

  it('flags ~/.ssh', async () => {
    const config = makeConfig('/h/.config/nanoclaw/mount-allowlist.json', { allowedPaths: ['~/.ssh'] });
    const result = await check.run(makeCtx({ configs: [config] }));
    expect(result.passed).toBe(false);
    expect(result.evidence?.[0].detail).toMatch(/credentials directory/);
  });

  it('flags /etc', async () => {
    const config = makeConfig('/h/.config/nanoclaw/mount-allowlist.json', { allowedPaths: ['/etc'] });
    const result = await check.run(makeCtx({ configs: [config] }));
    expect(result.passed).toBe(false);
  });

  it('flags entire home expansion', async () => {
    const config = makeConfig('/h/.config/nanoclaw/mount-allowlist.json', { allowedPaths: ['/home/test'] });
    const result = await check.run(makeCtx({ configs: [config], fs: makeMemFs({ homedir: '/home/test' }) }));
    expect(result.passed).toBe(false);
    expect(result.evidence?.[0].detail).toMatch(/entire user home/);
  });

  it('passes for narrow project paths', async () => {
    const config = makeConfig('/h/.config/nanoclaw/mount-allowlist.json', { allowedPaths: ['/home/test/projects/foo', '/tmp/scratch'] });
    const result = await check.run(makeCtx({ configs: [config], fs: makeMemFs({ homedir: '/home/test' }) }));
    expect(result.passed).toBe(true);
  });

  it('handles object entries with path field', async () => {
    const config = makeConfig('/h/.config/nanoclaw/mount-allowlist.json', { allowedPaths: [{ path: '/etc', mode: 'r' }] });
    const result = await check.run(makeCtx({ configs: [config] }));
    expect(result.passed).toBe(false);
  });

  it('passes when no mount-allowlist.json present', async () => {
    const config = makeConfig('/h/.config/nanoclaw/config.json', { foo: 'bar' });
    const result = await check.run(makeCtx({ configs: [config] }));
    expect(result.passed).toBe(true);
  });
});

describe('NC-002: Mount Allowlist File Writable', () => {
  const check = nanoclawChecks.find(c => c.id === 'NC-002')!;
  let tmpRoot: string;

  beforeEach(() => {
    tmpRoot = mkdtempSync(join(tmpdir(), 'vaso-nc002-'));
  });

  afterEach(() => {
    rmSync(tmpRoot, { recursive: true, force: true });
  });

  it('passes for 0600', async () => {
    const path = join(tmpRoot, 'mount-allowlist.json');
    writeFileSync(path, '{}');
    chmodSync(path, 0o600);
    const config = makeConfig(path, {});
    const result = await check.run(makeCtx({ configs: [config], fs: new LocalFSProvider() }));
    expect(result.passed).toBe(true);
  });

  it('flags 0666', async () => {
    const path = join(tmpRoot, 'mount-allowlist.json');
    writeFileSync(path, '{}');
    chmodSync(path, 0o666);
    const config = makeConfig(path, {});
    const result = await check.run(makeCtx({ configs: [config], fs: new LocalFSProvider() }));
    expect(result.passed).toBe(false);
    expect(result.severity).toBe('critical');
  });
});

describe('NC-003: NANOCLAW_HOME Redirect', () => {
  const check = nanoclawChecks.find(c => c.id === 'NC-003')!;

  it('passes when unset and no env file value', async () => {
    const config = makeConfig('/h/.nanoclaw.env', {}, 'env');
    const result = await check.run(makeCtx({ configs: [config] }));
    expect(result.passed).toBe(true);
  });

  it('flags world-writable redirect via .env file (critical)', async () => {
    const config = makeConfig('/h/.nanoclaw.env', { NANOCLAW_HOME: '/tmp/agent-home' }, 'env');
    const result = await check.run(makeCtx({ configs: [config] }));
    expect(result.passed).toBe(false);
    expect(result.severity).toBe('critical');
  });

  it('flags non-home redirect with warning', async () => {
    const config = makeConfig('/h/.nanoclaw.env', { NANOCLAW_HOME: '/opt/agent' }, 'env');
    const result = await check.run(makeCtx({ configs: [config] }));
    expect(result.passed).toBe(false);
    expect(result.severity).toBe('warning');
  });

  it('passes when redirect is inside home', async () => {
    const config = makeConfig('/h/.nanoclaw.env', { NANOCLAW_HOME: '/home/test/nanoclaw-data' }, 'env');
    const result = await check.run(makeCtx({ configs: [config], fs: makeMemFs({ homedir: '/home/test' }) }));
    expect(result.passed).toBe(true);
  });

  it('honors NANOCLAW_HOME from ctx.fs.getEnv (not process.env), so snapshot scans work', async () => {
    const originalProcessValue = process.env.NANOCLAW_HOME;
    delete process.env.NANOCLAW_HOME;
    try {
      const result = await check.run(makeCtx({
        fs: makeMemFs({ env: { NANOCLAW_HOME: '/dev/shm/agent' } }),
      }));
      expect(result.passed).toBe(false);
      expect(result.severity).toBe('critical');
    } finally {
      if (originalProcessValue !== undefined) process.env.NANOCLAW_HOME = originalProcessValue;
    }
  });
});

describe('NC-004: NANOCLAW_PORT Bound Publicly', () => {
  const check = nanoclawChecks.find(c => c.id === 'NC-004')!;

  it('flags NANOCLAW_HOST=0.0.0.0', async () => {
    const config = makeConfig('/h/.nanoclaw.env', { NANOCLAW_HOST: '0.0.0.0', NANOCLAW_PORT: '8080' }, 'env');
    const result = await check.run(makeCtx({ configs: [config] }));
    expect(result.passed).toBe(false);
    expect(result.severity).toBe('warning');
  });

  it('flags NANOCLAW_PORT without HOST', async () => {
    const config = makeConfig('/h/.nanoclaw.env', { NANOCLAW_PORT: '8080' }, 'env');
    const result = await check.run(makeCtx({ configs: [config] }));
    expect(result.passed).toBe(false);
    expect(result.evidence?.[0].detail).toMatch(/without NANOCLAW_HOST/);
  });

  it('passes for loopback', async () => {
    const config = makeConfig('/h/.nanoclaw.env', { NANOCLAW_HOST: '127.0.0.1', NANOCLAW_PORT: '8080' }, 'env');
    const result = await check.run(makeCtx({ configs: [config] }));
    expect(result.passed).toBe(true);
  });

  it('passes when no PORT is configured', async () => {
    const config = makeConfig('/h/.nanoclaw.env', { NANOCLAW_HOME: '/tmp' }, 'env');
    const result = await check.run(makeCtx({ configs: [config] }));
    expect(result.passed).toBe(true);
  });
});

describe('NC-005: Skills Directory World-Writable', () => {
  const check = nanoclawChecks.find(c => c.id === 'NC-005')!;
  let tmpRoot: string;

  beforeEach(() => {
    tmpRoot = mkdtempSync(join(tmpdir(), 'vaso-nc005-'));
  });

  afterEach(() => {
    rmSync(tmpRoot, { recursive: true, force: true });
  });

  it('passes when skills dir is 0755', async () => {
    const skillsDir = join(tmpRoot, 'skills');
    mkdirSync(skillsDir);
    chmodSync(skillsDir, 0o755);
    const result = await check.run(makeCtx({
      installDir: tmpRoot,
      skillsDir,
      fs: new LocalFSProvider(),
    }));
    expect(result.passed).toBe(true);
  });

  it('flags 0777', async () => {
    const skillsDir = join(tmpRoot, 'skills');
    mkdirSync(skillsDir);
    chmodSync(skillsDir, 0o777);
    const result = await check.run(makeCtx({
      installDir: tmpRoot,
      skillsDir,
      fs: new LocalFSProvider(),
    }));
    expect(result.passed).toBe(false);
  });

  it('passes when skills dir does not exist', async () => {
    const result = await check.run(makeCtx({
      installDir: tmpRoot,
      skillsDir: join(tmpRoot, 'nonexistent'),
      fs: new LocalFSProvider(),
    }));
    expect(result.passed).toBe(true);
  });
});
