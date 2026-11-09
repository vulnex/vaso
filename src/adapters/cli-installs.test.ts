import { describe, it, expect, vi } from 'vitest';
import type { FSProvider, DirentInfo } from '../core/fs-provider.js';
import { cliInstallGlobs, discoverCliInstalls, type CliInstallSpec } from './cli-installs.js';

interface FakeHost {
  /** Existing binaries → version they report. */
  bins: Record<string, string>;
  which?: string;
  nvm?: string[];
  links?: Record<string, string>;
  kind?: 'local' | 'snapshot';
  /** Extra directory listings (path → entry names). */
  dirs?: Record<string, string[]>;
  /** Readable file contents (e.g. nvm alias files). */
  files?: Record<string, string>;
}

function makeFs(h: FakeHost): FSProvider {
  const nvmRoot = '/home/t/.nvm/versions/node';
  return {
    homedir: () => '/home/t',
    platform: 'linux',
    kind: h.kind ?? 'local',
    access: vi.fn(async (p: string) => p in h.bins),
    realpath: vi.fn(async (p: string) => h.links?.[p] ?? p),
    readFile: vi.fn(async (p: string) => {
      if (h.files && p in h.files) return h.files[p];
      throw new Error('ENOENT');
    }),
    readdirEntries: vi.fn(async (p: string) => {
      if (p === nvmRoot && h.nvm) return h.nvm.map(name => ({ name, isDirectory: true, isFile: false }) as DirentInfo);
      if (h.dirs?.[p]) return h.dirs[p].map(name => ({ name, isDirectory: true, isFile: false }) as DirentInfo);
      throw new Error('ENOENT');
    }),
    execSync: vi.fn((cmd: string) => {
      if (cmd === 'which' && h.which) return `${h.which}\n`;
      throw new Error('not found');
    }),
    getEnv: vi.fn(() => undefined),
  } as unknown as FSProvider;
}

function spec(h: FakeHost, extra: Partial<CliInstallSpec> = {}): CliInstallSpec {
  return { names: ['codex'], version: (bin) => h.bins[bin], ...extra };
}

describe('discoverCliInstalls', () => {
  it('finds scoped Volta package images (tools/image/packages/@scope/name/bin)', async () => {
    const volta = '/home/t/.volta/tools/image/packages';
    const host: FakeHost = {
      bins: { [`${volta}/@github/copilot/bin/copilot`]: '1.0.10' },
      dirs: { [volta]: ['@github', 'typescript'], [`${volta}/@github`]: ['copilot'] },
    };
    const r = await discoverCliInstalls('/home/t', makeFs(host), spec(host, { names: ['copilot'] }));
    expect(r.primary).toEqual({ path: `${volta}/@github/copilot/bin/copilot`, version: '1.0.10' });
  });

  it('prefers the PATH-resolved copy and reports every other version', async () => {
    const host: FakeHost = {
      which: '/opt/homebrew/bin/codex',
      bins: {
        '/usr/local/bin/codex': '0.144.4',
        '/opt/homebrew/bin/codex': '0.154.0',
      },
    };
    const r = await discoverCliInstalls('/home/t', makeFs(host), spec(host));
    expect(r.primary).toEqual({ path: '/opt/homebrew/bin/codex', version: '0.154.0' });
    expect(r.others).toEqual([{ path: '/usr/local/bin/codex', version: '0.144.4' }]);
  });

  it('finds copies in every nvm Node version', async () => {
    const host: FakeHost = {
      which: '/usr/local/bin/codex',
      nvm: ['v22.22.1', 'v24.21.0', 'v20.20.1'],
      bins: {
        '/usr/local/bin/codex': '0.111.0',
        '/usr/bin/codex': '0.130.0',
        '/home/t/.nvm/versions/node/v22.22.1/bin/codex': '0.154.0',
        '/home/t/.nvm/versions/node/v24.21.0/bin/codex': '0.158.0',
      },
    };
    const r = await discoverCliInstalls('/home/t', makeFs(host), spec(host));
    expect(r.primary?.version).toBe('0.111.0');
    expect(r.others.map(o => o.version).sort()).toEqual(['0.130.0', '0.154.0', '0.158.0']);
  });

  it('without a PATH match, the newest copy is primary', async () => {
    const host: FakeHost = {
      bins: {
        '/usr/local/bin/codex': '0.111.0',
        '/home/t/.local/bin/codex': '0.154.0',
      },
    };
    const r = await discoverCliInstalls('/home/t', makeFs(host), spec(host));
    expect(r.primary?.path).toBe('/home/t/.local/bin/codex');
    expect(r.others.map(o => o.version)).toEqual(['0.111.0']);
  });

  it('orders OpenClaw correction releases after their base release', async () => {
    const host: FakeHost = {
      bins: {
        '/usr/local/bin/codex': '2026.7.1-1',
        '/home/t/.local/bin/codex': '2026.7.1',
      },
    };
    const r = await discoverCliInstalls('/home/t', makeFs(host), { ...spec(host), versionOptions: { correctionSuffix: true } });
    expect(r.primary?.version).toBe('2026.7.1-1');
    const plain = await discoverCliInstalls('/home/t', makeFs(host), spec(host));
    expect(plain.primary?.version).toBe('2026.7.1');
  });

  it('collapses symlinked duplicates and same-version copies', async () => {
    const host: FakeHost = {
      which: '/usr/bin/codex',
      links: { '/usr/local/bin/codex': '/usr/bin/codex' },
      nvm: ['v22.22.1', 'v24.21.0'],
      bins: {
        '/usr/bin/codex': '0.130.0',
        '/usr/local/bin/codex': '0.130.0',
        '/home/t/.nvm/versions/node/v22.22.1/bin/codex': '0.154.0',
        '/home/t/.nvm/versions/node/v24.21.0/bin/codex': '0.154.0',
      },
    };
    const r = await discoverCliInstalls('/home/t', makeFs(host), spec(host));
    expect(r.primary?.path).toBe('/usr/bin/codex');
    expect(r.others).toHaveLength(1);
    expect(r.others[0].version).toBe('0.154.0');
  });

  it('on a snapshot only the PATH-resolved copy may be executed', async () => {
    const host: FakeHost = {
      kind: 'snapshot',
      which: '/home/t/.local/bin/codex',
      bins: { '/home/t/.local/bin/codex': '0.154.0', '/usr/local/bin/codex': '0.111.0' },
    };
    const calls: Array<[string, boolean]> = [];
    const r = await discoverCliInstalls('/home/t', makeFs(host), spec(host, {
      version: (bin, canExec) => { calls.push([bin, canExec]); return host.bins[bin]; },
    }));
    expect(calls).toEqual([['/home/t/.local/bin/codex', true], ['/usr/local/bin/codex', false]]);
    expect(r.others).toHaveLength(1);
  });

  it('drops unversioned copies on snapshots (a second link to the same install) but keeps them locally', async () => {
    const bins = { '/home/t/.local/bin/codex': '0.154.0', '/home/t/.bun/bin/codex': '' };
    const version = (bin: string) => bins[bin as keyof typeof bins] || undefined;
    for (const [kind, expected] of [['snapshot', 0], ['local', 1]] as const) {
      const host: FakeHost = { kind, which: '/home/t/.local/bin/codex', bins };
      const r = await discoverCliInstalls('/home/t', makeFs(host), spec(host, { version }));
      expect(r.others, kind).toHaveLength(expected);
    }
  });

  it('finds copies under fnm, asdf, mise, n and pnpm', async () => {
    const host: FakeHost = {
      which: '/opt/homebrew/bin/codex',
      dirs: {
        '/home/t/.local/share/fnm/node-versions': ['v20.1.0'],
        '/home/t/.asdf/installs/nodejs': ['22.0.0'],
        '/home/t/.local/share/mise/installs/node': ['24.1.0'],
        '/usr/local/n/versions/node': ['18.0.0'],
      },
      bins: {
        '/opt/homebrew/bin/codex': '0.160.0',
        '/home/t/.local/share/fnm/node-versions/v20.1.0/installation/bin/codex': '0.100.0',
        '/home/t/.asdf/installs/nodejs/22.0.0/bin/codex': '0.110.0',
        '/home/t/.local/share/mise/installs/node/24.1.0/bin/codex': '0.120.0',
        '/usr/local/n/versions/node/18.0.0/bin/codex': '0.90.0',
        '/home/t/.local/share/pnpm/codex': '0.130.0',
      },
    };
    const r = await discoverCliInstalls('/home/t', makeFs(host), spec(host));
    expect(r.others.map(o => o.version).sort()).toEqual(['0.100.0', '0.110.0', '0.120.0', '0.130.0', '0.90.0']);
  });

  it('reports versions an updater retains on disk, versioned by name, skipping the active one', async () => {
    const store = '/home/t/.local/share/claude/versions';
    const host: FakeHost = {
      which: '/home/t/.local/bin/claude',
      links: { '/home/t/.local/bin/claude': `${store}/2.1.270` },
      dirs: { [store]: ['2.1.270', '2.1.71', 'current'] },
      bins: {
        '/home/t/.local/bin/claude': '2.1.270',
        [`${store}/2.1.270`]: 'x',
        [`${store}/2.1.71`]: 'x',
        [`${store}/current`]: 'x',
      },
    };
    const version = vi.fn((bin: string) => host.bins[bin]);
    const r = await discoverCliInstalls('/home/t', makeFs(host), {
      names: ['claude'], retainedVersions: [{ dir: '.local/share/claude/versions' }], version,
    });
    expect(r.primary).toEqual({ path: '/home/t/.local/bin/claude', version: '2.1.270' });
    expect(r.others).toEqual([{ path: `${store}/2.1.71`, version: '2.1.71' }]);
    // Retained versions come from the entry name — never executed
    expect(version.mock.calls.map(c => c[0])).not.toContain(`${store}/2.1.71`);
  });

  it('retained versions with a binary inside each version dir', async () => {
    const store = '/home/t/.local/share/cursor-agent/versions';
    const host: FakeHost = {
      kind: 'snapshot',
      which: '/home/t/.local/bin/cursor-agent',
      dirs: { [store]: ['2026.04.28-e984b46', '2026.09.23-86fc751'] },
      bins: {
        '/home/t/.local/bin/cursor-agent': '2026.09.23-86fc751',
        [`${store}/2026.04.28-e984b46/cursor-agent`]: 'x',
        [`${store}/2026.09.23-86fc751/cursor-agent`]: 'x',
      },
    };
    const r = await discoverCliInstalls('/home/t', makeFs(host), {
      names: ['cursor-agent'],
      retainedVersions: [{ dir: '.local/share/cursor-agent/versions', binary: 'cursor-agent' }],
      version: (bin) => host.bins[bin],
    });
    // Snapshot: no realpath, but the active version equals the primary's and collapses
    expect(r.others).toEqual([{ path: `${store}/2026.04.28-e984b46/cursor-agent`, version: '2026.04.28-e984b46' }]);
  });

  it("prefers nvm's default Node copy over a system copy a non-interactive PATH finds", async () => {
    const nvm = '/home/t/.nvm/versions/node';
    const host: FakeHost = {
      which: '/usr/local/bin/codex',
      nvm: ['v22.22.1', 'v24.21.0', 'v22.3.0'],
      files: { '/home/t/.nvm/alias/default': '22\n' },
      bins: {
        '/usr/local/bin/codex': '0.111.0',
        [`${nvm}/v22.22.1/bin/codex`]: '0.154.0',
        [`${nvm}/v24.21.0/bin/codex`]: '0.158.0',
      },
    };
    const r = await discoverCliInstalls('/home/t', makeFs(host), spec(host));
    expect(r.primary).toEqual({ path: `${nvm}/v22.22.1/bin/codex`, version: '0.154.0' });
    expect(r.others.map(o => o.version).sort()).toEqual(['0.111.0', '0.158.0']);
  });

  it('keeps the PATH copy when nvm default is system, unresolvable, or which already hit nvm', async () => {
    const nvm = '/home/t/.nvm/versions/node';
    const bins = { '/usr/local/bin/codex': '0.111.0', [`${nvm}/v22.22.1/bin/codex`]: '0.154.0', [`${nvm}/v24.21.0/bin/codex`]: '0.158.0' };
    for (const [alias, which, expected] of [
      ['system', '/usr/local/bin/codex', '0.111.0'],
      ['18', '/usr/local/bin/codex', '0.111.0'],
      ['22', `${nvm}/v24.21.0/bin/codex`, '0.158.0'],
    ] as const) {
      const host: FakeHost = { which, nvm: ['v22.22.1', 'v24.21.0'], files: { '/home/t/.nvm/alias/default': alias }, bins };
      const r = await discoverCliInstalls('/home/t', makeFs(host), spec(host));
      expect(r.primary?.version, alias).toBe(expected);
    }
  });

  it('keeps a user-dir PATH hit over the nvm default copy (user dirs often precede nvm)', async () => {
    const nvm = '/home/t/.nvm/versions/node';
    const host: FakeHost = {
      which: '/home/t/.local/bin/openclaw',
      nvm: ['v22.22.1'],
      files: { '/home/t/.nvm/alias/default': '22' },
      bins: { '/home/t/.local/bin/openclaw': '2026.9.4', [`${nvm}/v22.22.1/bin/openclaw`]: '2026.3.13' },
    };
    const r = await discoverCliInstalls('/home/t', makeFs(host), { ...spec(host), names: ['openclaw'] });
    expect(r.primary?.version).toBe('2026.9.4');
    expect(r.others).toEqual([{ path: `${nvm}/v22.22.1/bin/openclaw`, version: '2026.3.13' }]);
  });

  it('on a snapshot, the nvm-default primary is versioned from files, not the PATH copy output', async () => {
    const nvm = '/home/t/.nvm/versions/node';
    const host: FakeHost = {
      kind: 'snapshot',
      which: '/usr/local/bin/codex',
      nvm: ['v22.22.1'],
      files: { '/home/t/.nvm/alias/default': '22' },
      bins: { '/usr/local/bin/codex': '0.111.0', [`${nvm}/v22.22.1/bin/codex`]: '0.154.0' },
    };
    const calls: Array<[string, boolean]> = [];
    const r = await discoverCliInstalls('/home/t', makeFs(host), spec(host, {
      version: (bin, canExec) => { calls.push([bin, canExec]); return host.bins[bin]; },
    }));
    expect(r.primary).toEqual({ path: `${nvm}/v22.22.1/bin/codex`, version: '0.154.0' });
    expect(calls).toContainEqual([`${nvm}/v22.22.1/bin/codex`, false]);
    expect(calls).toContainEqual(['/usr/local/bin/codex', true]);
  });

  it('resolves lts/<name> and node aliases', async () => {
    const nvm = '/home/t/.nvm/versions/node';
    const bins = { '/usr/bin/codex': '0.1.0', [`${nvm}/v20.20.1/bin/codex`]: '0.2.0', [`${nvm}/v24.21.0/bin/codex`]: '0.3.0' };
    const lts: FakeHost = { which: '/usr/bin/codex', nvm: ['v20.20.1', 'v24.21.0'], bins,
      files: { '/home/t/.nvm/alias/default': 'lts/iron', '/home/t/.nvm/alias/lts/iron': 'v20.20.1' } };
    expect((await discoverCliInstalls('/home/t', makeFs(lts), spec(lts))).primary?.version).toBe('0.2.0');
    const node: FakeHost = { ...lts, files: { '/home/t/.nvm/alias/default': 'node' } };
    expect((await discoverCliInstalls('/home/t', makeFs(node), spec(node))).primary?.version).toBe('0.3.0');
  });

  it('returns nothing when no copy exists', async () => {
    const host: FakeHost = { bins: {} };
    expect(await discoverCliInstalls('/home/t', makeFs(host), spec(host))).toEqual({ others: [] });
  });
});

describe('cliInstallGlobs', () => {
  it('surfaces scoped Volta package images to the probe', () => {
    expect(cliInstallGlobs(['copilot'])).toContain('~/.volta/tools/image/packages/@*/*/bin/copilot');
  });
});

describe('local CLI resolution PATH matches the probe', () => {
  it('uses the same user and system bin dirs as probe/collector.go', async () => {
    const { readFileSync } = await import('node:fs');
    const { PROBE_USER_BIN_DIRS, PROBE_SYSTEM_BIN_DIRS } = await import('./cli-installs.js');
    const go = readFileSync(new URL('../../probe/collector.go', import.meta.url), 'utf-8');
    const list = (name: string) => [...(go.match(new RegExp(`var ${name} = \\[\\]string\\{([\\s\\S]*?)\\n\\}`))?.[1] ?? '')
      .matchAll(/"([^"]+)"/g)].map(m => m[1]);
    expect(PROBE_USER_BIN_DIRS).toEqual(list('userBinDirs'));
    const sys = go.match(/var systemBinDirs = \[\]string\{([^}]*)\}/)?.[1] ?? '';
    expect(PROBE_SYSTEM_BIN_DIRS).toEqual([...sys.matchAll(/"([^"]+)"/g)].map(m => m[1]));
  });
});

describe('discoverCliInstalls resolves `which` like the probe', () => {
  it('gives which the user bin dirs first (non-root) and last (root)', async () => {
    const { discoverCliInstalls } = await import('./cli-installs.js');
    const seen: string[] = [];
    const fake = (root: boolean) => ({
      kind: 'local', platform: 'linux', homedir: () => '/home/u',
      getEnv: (k: string) => (k === 'PATH' ? '/usr/bin:/bin' : undefined),
      isPrivileged: () => root,
      execSync: (_c: string, _a: string[], o?: { path?: string }) => { seen.push(o?.path ?? ''); throw new Error('nf'); },
      access: async () => false, stat: async () => { throw new Error('ENOENT'); },
      readdir: async () => [], readdirEntries: async () => [], realpath: async (p: string) => p,
      exec: async () => ({ exitCode: 1, stdout: '', stderr: '' }),
    }) as unknown as import('../core/fs-provider.js').FSProvider;
    await discoverCliInstalls('/home/u', fake(false), { names: ['tool'], nvm: false, version: async () => undefined });
    expect(seen[0].split(':').slice(0, 2)).toEqual(['/home/u/.local/bin', '/home/u/.bun/bin']);
    expect(seen[0]).toContain('/usr/bin:/bin:/opt/homebrew/bin');
    seen.length = 0;
    await discoverCliInstalls('/home/u', fake(true), { names: ['tool'], nvm: false, version: async () => undefined });
    expect(seen[0].startsWith('/usr/bin:/bin:')).toBe(true);
    expect(seen[0].endsWith('/home/u/bin')).toBe(true);
  });
});
