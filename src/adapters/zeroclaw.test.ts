import { describe, it, expect, vi } from 'vitest';
import type { FSProvider } from '../core/fs-provider.js';
import { zeroclawAdapter, zeroclawDirs } from './zeroclaw.js';

interface FakeFs {
  files?: Record<string, string>;
  dirs?: string[];
  env?: Record<string, string>;
  platform?: NodeJS.Platform;
  which?: string;
  version?: string;
}

function makeFs(o: FakeFs = {}): FSProvider {
  const files = o.files ?? {};
  const dirs = new Set(o.dirs ?? []);
  return {
    homedir: () => '/home/t',
    platform: o.platform ?? 'linux',
    access: vi.fn(async (p: string) => p in files || dirs.has(p)),
    readFile: vi.fn(async (p: string) => {
      if (p in files) return files[p];
      throw new Error(`ENOENT ${p}`);
    }),
    stat: vi.fn(async (p: string) => ({ mode: 0o100600, isFile: () => p in files, isDirectory: () => dirs.has(p) })),
    readdirEntries: vi.fn(async (p: string) => {
      const prefix = `${p}/`;
      const names = new Set<string>();
      for (const d of dirs) {
        if (d.startsWith(prefix)) names.add(d.slice(prefix.length).split('/')[0]);
      }
      return [...names].map(name => ({ name, isFile: false, isDirectory: true }));
    }),
    realpath: vi.fn(async (p: string) => p),
    execSync: vi.fn((cmd: string, args: string[]) => {
      if (cmd === 'which' && args[0] === 'zeroclaw' && o.which) return o.which;
      if (args[0] === '--version' && o.version) return o.version;
      throw new Error('not found');
    }),
    getEnv: vi.fn((k: string) => o.env?.[k]),
  } as unknown as FSProvider;
}

/** `zeroclaw config set` output for a fresh 0.8.5 install (upstream defaults). */
const V3 = `schema_version = 3

[providers]

[agents.assistant]
enabled = true
model_provider = "ollama.local"
risk_profile = "balanced"

[risk_profiles.balanced]
level = "supervised"
workspace_only = true

[providers.models.ollama.local]
model = "llama3.2"

[agents.assistant.workspace]
unrestricted_filesystem = false

[risk_profiles]
`;

const DIR = '/home/t/.zeroclaw';

describe('ZeroClaw adapter', () => {
  it('returns nothing when neither config nor binary exists', async () => {
    expect(await zeroclawAdapter.detect({ fs: makeFs() })).toEqual([]);
  });

  it('detects a V3 install: config + auth store, per-agent skills, gateway defaults, models, version', async () => {
    const fs = makeFs({
      dirs: [DIR, `${DIR}/agents/assistant/workspace/skills`, `${DIR}/shared/skills`],
      files: {
        [`${DIR}/config.toml`]: V3,
        [`${DIR}/auth-profiles.json`]: '{"schema_version":1,"profiles":{}}',
        '/home/t/.cargo/bin/zeroclaw': '',
      },
      version: 'zeroclaw 0.8.5 (a1b2c3d)',
    });
    const [inst] = await zeroclawAdapter.detect({ fs });
    expect(inst.installDir).toBe(DIR);
    expect(inst.configFiles.map(c => c.filePath)).toEqual([`${DIR}/config.toml`, `${DIR}/auth-profiles.json`]);
    expect(inst.version).toBe('0.8.5');
    expect(inst.cliBinary).toBe('/home/t/.cargo/bin/zeroclaw');
    expect(inst.skillsDirs).toEqual([`${DIR}/agents/assistant/workspace/skills`, `${DIR}/shared/skills`]);
    expect(inst.skillsDir).toBe(`${DIR}/agents/assistant/workspace/skills`);
    expect(inst.gateway).toEqual({ host: '127.0.0.1', port: 42617, authMode: 'pairing', tls: false });
    expect(inst.models).toEqual([{ id: 'llama3.2', provider: 'ollama' }]);
  });

  it('honours ZEROCLAW_CONFIG_DIR from the scanned host', async () => {
    const fs = makeFs({
      dirs: ['/etc/zeroclaw'],
      files: { '/etc/zeroclaw/config.toml': V3 },
      env: { ZEROCLAW_CONFIG_DIR: '/etc/zeroclaw' },
    });
    const [inst] = await zeroclawAdapter.detect({ fs });
    expect(inst.installDir).toBe('/etc/zeroclaw');
  });

  it('resolves ZEROCLAW_DATA_DIR / deprecated ZEROCLAW_WORKSPACE like upstream', async () => {
    // Data dir holding its own config.toml is the config dir.
    let fs = makeFs({ files: { '/srv/zc/config.toml': V3 }, env: { ZEROCLAW_DATA_DIR: '/srv/zc' } });
    expect(await zeroclawDirs('/home/t', fs)).toEqual({ configDir: '/srv/zc', dataDir: '/srv/zc/data' });
    // A `.../data` dir resolves to the sibling .zeroclaw config dir.
    fs = makeFs({ env: { ZEROCLAW_WORKSPACE: '/srv/inst/data' } });
    expect(await zeroclawDirs('/home/t', fs)).toEqual({ configDir: '/srv/inst/.zeroclaw', dataDir: '/srv/inst/data' });
    // CONFIG_DIR wins over DATA_DIR; ~ expands against the scanned home.
    fs = makeFs({ env: { ZEROCLAW_CONFIG_DIR: '~/zc', ZEROCLAW_DATA_DIR: '/srv/zc' } });
    expect((await zeroclawDirs('/home/t', fs)).configDir).toBe('/home/t/zc');
  });

  it('falls back to the Homebrew config dir on macOS', async () => {
    const fs = makeFs({ platform: 'darwin', files: { '/opt/homebrew/var/zeroclaw/config.toml': V3 } });
    expect((await zeroclawDirs('/home/t', fs)).configDir).toBe('/opt/homebrew/var/zeroclaw');
  });

  it('adds a custom agent workspace, bundle directories and the open-skills checkout', async () => {
    const cfg = `${V3}
[agents.coder]
risk_profile = "balanced"
[agents.coder.workspace]
path = "~/work/coder"
[skill_bundles.team]
directory = "shared/skills/team"
[skills]
open_skills_enabled = true
`;
    const fs = makeFs({
      dirs: [DIR, '/home/t/work/coder/skills', `${DIR}/shared/skills/team`, '/home/t/open-skills'],
      files: { [`${DIR}/config.toml`]: cfg },
    });
    const [inst] = await zeroclawAdapter.detect({ fs });
    expect(inst.skillsDirs).toEqual(['/home/t/work/coder/skills', `${DIR}/shared/skills/team`, '/home/t/open-skills']);
  });

  it('reports a binary-only install with shared/skills as the skills dir', async () => {
    const fs = makeFs({ files: { '/home/t/.cargo/bin/zeroclaw': '' }, version: 'zeroclaw 0.8.5' });
    const [inst] = await zeroclawAdapter.detect({ fs });
    expect(inst.configFiles).toEqual([]);
    expect(inst.skillsDir).toBe(`${DIR}/shared/skills`);
    expect(inst.gateway).toBeUndefined();
  });

  it('reads [gateway] overrides', () => {
    expect(zeroclawAdapter.getGatewayInfo({
      gateway: { host: '0.0.0.0', port: 8080, require_pairing: false, tls: { enabled: true } },
    })).toEqual({ host: '0.0.0.0', port: 8080, authMode: 'none', tls: true });
  });

  it('declares credential stores and keeps private data metadata-only in the probe manifest', () => {
    expect(zeroclawAdapter.getCredentialPaths!(DIR)).toEqual([
      `${DIR}/config.toml`, `${DIR}/auth-profiles.json`, `${DIR}/.secret_key`, `${DIR}/config.toml.backup`,
    ]);
    const m = zeroclawAdapter.getProbeManifest!();
    expect(m.metadataGlobPatterns).toEqual(expect.arrayContaining([
      '~/.zeroclaw/.secret_key', '~/.zeroclaw/data/*', '~/.zeroclaw/data/*/*', '~/.zeroclaw/agents/*/workspace/*.md',
    ]));
    expect(m.filePaths).not.toContain('~/.zeroclaw/.secret_key');
    expect(m.globPatterns).toEqual(expect.arrayContaining(['~/.zeroclaw/agents/*/workspace/skills/**', '~/.zeroclaw/shared/skills/**']));
    expect(zeroclawAdapter.getCLICommand!()).toBe('zeroclaw');
  });
});
