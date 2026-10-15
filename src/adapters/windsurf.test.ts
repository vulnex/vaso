import { describe, it, expect } from 'vitest';
import type { FSProvider } from '../core/fs-provider.js';
import { windsurfAdapter } from './windsurf.js';

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
