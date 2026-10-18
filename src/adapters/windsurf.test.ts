import { describe, it, expect, vi, afterEach } from 'vitest';
import type { FSProvider } from '../core/fs-provider.js';
import { windsurfAdapter } from './windsurf.js';
import { captureConfigLoadErrors } from '../core/config-loader.js';

const HOME = '/home/tester';

function product(windsurfVersion: string, applicationName = 'devin-desktop'): string {
  return JSON.stringify({ applicationName, windsurfVersion, version: '1.110.0' });
}

function makeFs(
  files: Record<string, string | Uint8Array>,
  opts: { platform?: NodeJS.Platform; which?: Record<string, string>; realpaths?: Record<string, string> } = {},
): FSProvider {
  const paths = new Set(Object.keys(files));
  // Every ancestor dir of a file exists too
  for (const p of Object.keys(files)) {
    let d = p;
    while ((d = d.slice(0, d.lastIndexOf('/'))) && d.length > 0) paths.add(d);
  }
  return {
    platform: opts.platform ?? 'linux',
    homedir: () => HOME,
    getEnv: () => undefined,
    access: async (p: string) => paths.has(p),
    readFile: async (p: string) => {
      if (!(p in files)) throw new Error(`ENOENT ${p}`);
      return files[p];
    },
    readBytes: async (p: string) => {
      if (!(p in files)) throw new Error(`ENOENT ${p}`);
      const v = files[p];
      return typeof v === 'string' ? new TextEncoder().encode(v) : v;
    },
    realpath: async (p: string) => opts.realpaths?.[p] ?? p,
    execSync: (cmd: string, args: string[]) => {
      const hit = cmd === 'which' ? opts.which?.[args[0]] : undefined;
      if (!hit) throw new Error('not found');
      return hit;
    },
  } as unknown as FSProvider;
}

describe('Windsurf / Devin Desktop adapter — install root + version', () => {
  it('reads the version from a home-dir tarball extract on Linux (~/devin-desktop)', async () => {
    const fs = makeFs({
      [`${HOME}/devin-desktop/resources/app/product.json`]: product('3.10.35'),
      [`${HOME}/.config/Devin/User/settings.json`]: '{}',
    });
    const [inst] = await windsurfAdapter.detect({ fs });
    expect(inst.version).toBe('3.10.35');
    expect(inst.agentName).toBe('Devin Desktop');
    expect(inst.appBundle).toBe(`${HOME}/devin-desktop`);
  });

  it('detects a tarball install even before first run (no user-data dirs yet)', async () => {
    const fs = makeFs({ [`${HOME}/Windsurf/resources/app/product.json`]: product('1.9566.11', 'windsurf') });
    const [inst] = await windsurfAdapter.detect({ fs });
    expect(inst.version).toBe('1.9566.11');
    expect(inst.agentName).toBeUndefined();
  });

  it('resolves a package install through the CLI launcher symlink', async () => {
    const fs = makeFs(
      {
        '/usr/share/windsurf/resources/app/product.json': product('1.12.0', 'windsurf'),
        '/usr/share/windsurf/bin/windsurf': '',
      },
      {
        which: { windsurf: '/usr/local/lib/links/windsurf' },
        realpaths: { '/usr/local/lib/links/windsurf': '/usr/share/windsurf/bin/windsurf' },
      },
    );
    const [inst] = await windsurfAdapter.detect({ fs });
    expect(inst.version).toBe('1.12.0');
    expect(inst.appBundle).toBe('/usr/share/windsurf');
  });

  it('keeps the macOS app-bundle path unchanged', async () => {
    const fs = makeFs(
      { '/Applications/Devin.app/Contents/Resources/app/product.json': product('3.10.35') },
      { platform: 'darwin' },
    );
    const [inst] = await windsurfAdapter.detect({ fs });
    expect(inst.version).toBe('3.10.35');
    expect(inst.appBundle).toBe('/Applications/Devin.app');
  });

  it('reports nothing when no install signal exists', async () => {
    expect(await windsurfAdapter.detect({ fs: makeFs({}) })).toEqual([]);
  });

  it('loads 3.x user_settings.pb and the shared Devin config.json', async () => {
    // field 27 = 3 (Turbo), field 85 = "bash"
    const pb = new Uint8Array([0xd8, 0x01, 3, 0xaa, 0x05, 4, ...new TextEncoder().encode('bash')]);
    const fs = makeFs({
      [`${HOME}/devin-desktop/resources/app/product.json`]: product('3.10.35'),
      [`${HOME}/.codeium/windsurf/user_settings.pb`]: pb,
      [`${HOME}/.config/devin/config.json`]: '{ // jsonc\n "permissions": { "allow": ["exec"] } }',
    });
    const [inst] = await windsurfAdapter.detect({ fs });
    const pbConfig = inst.configFiles.find(c => c.filePath.endsWith('user_settings.pb'))!;
    expect(pbConfig.data).toEqual({
      windsurf: { autoExecutionPolicy: 'turbo', cascadeCommandsAllowList: ['bash'] },
    });
    const devinConfig = inst.configFiles.find(c => c.filePath.endsWith('/.config/devin/config.json'))!;
    expect(devinConfig.data.permissions).toEqual({ allow: ['exec'] });
  });
});

describe('Windsurf / Devin Desktop adapter — files shared with Devin CLI', () => {
  const shared = {
    [`${HOME}/.codeium/windsurf/mcp_config.json`]: '{ "mcpServers": {} }',
    [`${HOME}/.config/devin/mcp_config.json`]: '{ "mcpServers": {} }',
    [`${HOME}/.config/devin/config.json`]: '{ "permissions": { "allow": ["exec"] } }',
  };

  it('loads ~/.config/devin/{mcp_config,config}.json when Devin CLI is absent', async () => {
    const [inst] = await windsurfAdapter.detect({ fs: makeFs(shared) });
    expect(inst.configFiles.map(c => c.filePath)).toEqual([
      `${HOME}/.codeium/windsurf/mcp_config.json`,
      `${HOME}/.config/devin/mcp_config.json`,
      `${HOME}/.config/devin/config.json`,
    ]);
  });

  it('leaves them to the Devin CLI install when the CLI is installed (no double counting)', async () => {
    const fs = makeFs({ ...shared, [`${HOME}/.local/bin/devin`]: '' });
    const [inst] = await windsurfAdapter.detect({ fs });
    expect(inst.configFiles.map(c => c.filePath)).toEqual([`${HOME}/.codeium/windsurf/mcp_config.json`]);
  });
});

describe('Windsurf / Devin Desktop adapter — Cascade skill roots (dt15)', () => {
  const skills = {
    [`${HOME}/.codeium/windsurf/skills/evil/SKILL.md`]: '# evil',
    [`${HOME}/.config/devin/skills/evil/SKILL.md`]: '# evil',
    [`${HOME}/.agents/skills/evil/SKILL.md`]: '# evil',
  };
  afterEach(() => vi.restoreAllMocks());

  it('records the global skill roots when Devin CLI is absent', async () => {
    vi.spyOn(process, 'cwd').mockReturnValue('/nowhere');
    const [inst] = await windsurfAdapter.detect({ fs: makeFs(skills) });
    expect(inst.skillsDirs).toEqual([
      `${HOME}/.codeium/windsurf/skills`, `${HOME}/.config/devin/skills`, `${HOME}/.agents/skills`,
    ]);
  });

  it('leaves the roots shared with Devin CLI to its install (findings not doubled)', async () => {
    vi.spyOn(process, 'cwd').mockReturnValue('/nowhere');
    const [inst] = await windsurfAdapter.detect({ fs: makeFs({ ...skills, [`${HOME}/.local/bin/devin`]: '' }) });
    expect(inst.skillsDirs).toEqual([`${HOME}/.codeium/windsurf/skills`]);
  });

  it('adds legacy workspace .windsurf/skills from the repo root down to cwd', async () => {
    vi.spyOn(process, 'cwd').mockReturnValue('/work/app/pkg');
    const fs = makeFs({
      [`${HOME}/.codeium/windsurf/mcp_config.json`]: '{}',
      '/work/app/.git/HEAD': '',
      '/work/app/.windsurf/skills/a/SKILL.md': '# a',
      '/work/app/pkg/.windsurf/skills/b/SKILL.md': '# b',
    });
    const [inst] = await windsurfAdapter.detect({ fs });
    expect(inst.skillsDirs).toEqual(['/work/app/.windsurf/skills', '/work/app/pkg/.windsurf/skills']);
    expect(inst.skillsDir).toBe('/work/app/.windsurf/skills');
  });

  it('records no skill roots when none exist', async () => {
    vi.spyOn(process, 'cwd').mockReturnValue('/nowhere');
    const [inst] = await windsurfAdapter.detect({ fs: makeFs({ [`${HOME}/.codeium/windsurf/mcp_config.json`]: '{}' }) });
    expect(inst.skillsDirs).toBeUndefined();
  });
});

describe('Windsurf / Devin Desktop adapter — Linux $XDG_CONFIG_HOME (dt15)', () => {
  it('reads editor settings and declares state.vscdb under $XDG_CONFIG_HOME', async () => {
    const base = makeFs({ '/xdg/Windsurf/User/settings.json': '{ "windsurf.autoExecutionPolicy": "turbo" }' });
    const fs = { ...base, getEnv: (k: string) => (k === 'XDG_CONFIG_HOME' ? '/xdg' : undefined) } as FSProvider;
    const [inst] = await windsurfAdapter.detect({ fs });
    expect(inst.configFiles.map(c => c.filePath)).toEqual(['/xdg/Windsurf/User/settings.json']);
    expect(windsurfAdapter.getCredentialPaths!(inst.installDir, fs)).toContain('/xdg/Windsurf/User/globalStorage/state.vscdb');
  });

  it('keeps ~/.config without XDG_CONFIG_HOME (or with a relative one, which XDG ignores)', async () => {
    const base = makeFs({ [`${HOME}/.config/Devin/User/settings.json`]: '{}' });
    const fs = { ...base, getEnv: (k: string) => (k === 'XDG_CONFIG_HOME' ? 'rel/dir' : undefined) } as FSProvider;
    const [inst] = await windsurfAdapter.detect({ fs });
    expect(inst.configFiles.map(c => c.filePath)).toEqual([`${HOME}/.config/Devin/User/settings.json`]);
  });
});

describe('Windsurf / Devin Desktop adapter — unreadable and broken configs (dt15)', () => {
  const denied = (p: string) => Object.assign(new Error(`EACCES: permission denied, open '${p}'`), { code: 'EACCES' });

  it('reports an unparseable settings.json, an unreadable Devin config.json and a truncated user_settings.pb as CONFIG-LOAD', async () => {
    const devinConfig = `${HOME}/.config/devin/config.json`;
    const base = makeFs({
      [`${HOME}/.codeium/windsurf/user_settings.pb`]: new Uint8Array([0x08, 0x03, 0xd8, 0x01, 0x03, 0xff, 0xff]),
      [`${HOME}/.config/Windsurf/User/settings.json`]: '{ "windsurf.autoExecutionPolicy": ',
      [devinConfig]: '',
    });
    const fs = {
      ...base,
      readFile: async (p: string) => {
        if (p === devinConfig) throw denied(p);
        return base.readFile(p);
      },
    } as FSProvider;
    const { result: [inst], loadErrors } = await captureConfigLoadErrors(() => windsurfAdapter.detect({ fs }));
    expect(loadErrors.map(e => [e.filePath.slice(HOME.length), e.stage])).toEqual([
      ['/.codeium/windsurf/user_settings.pb', 'parse'],
      ['/.config/devin/config.json', 'read'],
      ['/.config/Windsurf/User/settings.json', 'parse'],
    ]);
    expect(inst.configFiles.map(c => c.filePath)).toEqual([]);
  });

  it('still loads a JSONC settings.json with comments and trailing commas', async () => {
    const fs = makeFs({
      [`${HOME}/.config/Windsurf/User/settings.json`]: '{\n // turbo\n "windsurf.autoExecutionPolicy": "turbo",\n}',
    });
    const { result: [inst], loadErrors } = await captureConfigLoadErrors(() => windsurfAdapter.detect({ fs }));
    expect(loadErrors).toEqual([]);
    expect(inst.configFiles[0].data['windsurf.autoExecutionPolicy']).toBe('turbo');
  });
});
