import { describe, it, expect, vi, afterEach } from 'vitest';
import type { FSProvider } from '../core/fs-provider.js';
import { copilotCliAdapter } from './copilot-cli.js';
import { cursorCliAdapter } from './cursor-cli.js';

// Copilot CLI / Cursor adapter paths against an in-memory host (the adapters'
// own test files mock the config loader, so these live here).

const HOME = '/home/tester';

function fakeFs(
  files: Record<string, string>,
  opts: { env?: Record<string, string>; platform?: string; exec?: Record<string, string> } = {},
): FSProvider {
  const paths = new Set<string>();
  for (const key of Object.keys(files)) {
    let p = key.endsWith('/') ? key.slice(0, -1) : key;
    paths.add(p);
    while ((p = p.slice(0, p.lastIndexOf('/'))) && p.length > 0) paths.add(p);
  }
  return {
    kind: 'local',
    platform: opts.platform ?? 'linux',
    homedir: () => HOME,
    getEnv: (k: string) => opts.env?.[k],
    access: async (p: string) => paths.has(p),
    stat: async (p: string) => {
      if (!paths.has(p)) throw Object.assign(new Error(`ENOENT ${p}`), { code: 'ENOENT' });
      return { mode: 0o100600, isFile: () => p in files, isDirectory: () => !(p in files) };
    },
    readFile: async (p: string) => {
      if (!(p in files)) throw new Error(`ENOENT ${p}`);
      return files[p];
    },
    readdirEntries: async () => { throw new Error('ENOENT'); },
    realpath: async (p: string) => p,
    exec: async (cmd: string, args: string[]) => {
      const out = opts.exec?.[[cmd, ...args].join(' ')];
      return out === undefined ? { exitCode: 1, stdout: '', stderr: '' } : { exitCode: 0, stdout: out, stderr: '' };
    },
    execSync: (cmd: string, args: string[]) => {
      const out = opts.exec?.[[cmd, ...args].join(' ')];
      if (out === undefined) throw new Error('not found');
      return out;
    },
  } as unknown as FSProvider;
}

afterEach(() => vi.restoreAllMocks());

describe('Copilot CLI adapter paths', () => {
  it('records ~/.copilot/skills and ~/.agents/skills as skill roots', async () => {
    vi.spyOn(process, 'cwd').mockReturnValue('/nowhere');
    const fs = fakeFs({
      [`${HOME}/.copilot/settings.json`]: '{}',
      [`${HOME}/.copilot/skills/a/SKILL.md`]: '# a',
      [`${HOME}/.agents/skills/b/SKILL.md`]: '# b',
    });
    const [inst] = await copilotCliAdapter.detect({ fs });
    expect(inst.skillsDirs).toEqual([`${HOME}/.copilot/skills`, `${HOME}/.agents/skills`]);
  });

  it('loads permissions-config.json and the project .github/mcp.json', async () => {
    vi.spyOn(process, 'cwd').mockReturnValue('/work/app');
    const fs = fakeFs({
      [`${HOME}/.copilot/settings.json`]: '{}',
      [`${HOME}/.copilot/permissions-config.json`]: '{ "locations": {} }',
      '/work/app/.github/mcp.json': '{ "mcpServers": { "x": { "url": "http://mcp.example.com" } } }',
    });
    const installs = await copilotCliAdapter.detect({ fs });
    expect(installs[0].configFiles.map(c => c.filePath)).toContain(`${HOME}/.copilot/permissions-config.json`);
    const project = installs.find(i => i.profile === 'project')!;
    expect(project.configFiles.map(c => c.filePath)).toEqual(['/work/app/.github/mcp.json']);
  });
});

describe('Cursor adapter paths', () => {
  it('reads cli-config.json from CURSOR_CONFIG_DIR in place of ~/.cursor/cli-config.json', async () => {
    vi.spyOn(process, 'cwd').mockReturnValue('/nowhere');
    const fs = fakeFs({
      [`${HOME}/.cursor/cli-config.json`]: '{ "approvalMode": "allowlist" }',
      [`${HOME}/.cursor/mcp.json`]: '{}',
      '/etc/cursor-cfg/cli-config.json': '{ "approvalMode": "unrestricted" }',
    }, { env: { CURSOR_CONFIG_DIR: '/etc/cursor-cfg' } });
    const [inst] = await cursorCliAdapter.detect({ fs });
    const paths = inst.configFiles.map(c => c.filePath);
    expect(paths).toContain('/etc/cursor-cfg/cli-config.json');
    expect(paths).not.toContain(`${HOME}/.cursor/cli-config.json`);
  });

  it('records ~/.cursor/skills and ~/.agents/skills as skill roots', async () => {
    vi.spyOn(process, 'cwd').mockReturnValue('/nowhere');
    const fs = fakeFs({
      [`${HOME}/.cursor/cli-config.json`]: '{}',
      [`${HOME}/.cursor/skills/a/SKILL.md`]: '# a',
      [`${HOME}/.agents/skills/b/SKILL.md`]: '# b',
    });
    const [inst] = await cursorCliAdapter.detect({ fs });
    expect(inst.skillsDirs).toEqual([`${HOME}/.cursor/skills`, `${HOME}/.agents/skills`]);
  });

  it('lists the IDE app as another install when the CLI is primary, so advisories judge its version', async () => {
    vi.spyOn(process, 'cwd').mockReturnValue('/nowhere');
    const fs = fakeFs({
      [`${HOME}/.cursor/cli-config.json`]: '{}',
      [`${HOME}/.local/bin/cursor-agent`]: '',
      '/Applications/Cursor.app/Contents/Info.plist': '',
    }, {
      platform: 'darwin',
      exec: {
        [`${HOME}/.local/bin/cursor-agent --version`]: '2026.09.17-abc1234',
        'defaults read /Applications/Cursor.app/Contents/Info.plist CFBundleShortVersionString': '2.9.1',
      },
    });
    const [inst] = await cursorCliAdapter.detect({ fs });
    expect(inst.version).toMatch(/^2026\./);
    expect(inst.otherInstalls).toContainEqual({ path: '/Applications/Cursor.app', version: '2.9.1' });
  });
});
