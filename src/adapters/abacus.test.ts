import { describe, it, expect, vi, afterEach } from 'vitest';
import type { FSProvider } from '../core/fs-provider.js';
import { abacusAdapter } from './abacus.js';

const HOME = '/home/tester';

/** Files map to contents; a key ending in '/' declares an (empty) directory. */
function makeFs(files: Record<string, string>, platform: NodeJS.Platform = 'linux'): FSProvider {
  const paths = new Set<string>();
  for (const key of Object.keys(files)) {
    let p = key.endsWith('/') ? key.slice(0, -1) : key;
    paths.add(p);
    while ((p = p.slice(0, p.lastIndexOf('/'))) && p.length > 0) paths.add(p);
  }
  return {
    platform,
    homedir: () => HOME,
    getEnv: () => undefined,
    access: async (p: string) => paths.has(p),
    readFile: async (p: string) => {
      if (!(p in files)) throw new Error(`ENOENT ${p}`);
      return files[p];
    },
    readdirEntries: async () => [],
    realpath: async (p: string) => p,
    execSync: () => { throw new Error('not found'); },
    exec: async () => ({ exitCode: 1, stdout: '', stderr: '' }),
  } as unknown as FSProvider;
}

describe('Abacus.AI adapter', () => {
  afterEach(() => vi.restoreAllMocks());

  it('detects the CLI state dir and loads user + desktop configs', async () => {
    vi.spyOn(process, 'cwd').mockReturnValue('/somewhere/else');
    const fs = makeFs({
      [`${HOME}/.abacusai/config.json`]: '{ "permissionMode": "supervise", "model": "claude-sonnet-5", "smallModel": "ollama/qwen3" }',
      [`${HOME}/.abacusai/mcp.json`]: '{ "mcpServers": {} }',
      [`${HOME}/.abacusai/desktop/mcp-cowork.json`]: '{ "mcpServers": { "a": { "command": "x" } } }',
      [`${HOME}/.abacusai/desktop/agent-config-code.json`]: '{ "permissionMode": "auto" }',
      [`${HOME}/.abacusai/keystore.enc`]: 'bin',
      [`${HOME}/.abacusai/skills/`]: '',
    });
    const [inst] = await abacusAdapter.detect({ fs });

    expect(inst.agent).toBe('abacus');
    expect(inst.installDir).toBe(`${HOME}/.abacusai`);
    expect(inst.configFiles.map(c => c.filePath)).toEqual([
      `${HOME}/.abacusai/config.json`,
      `${HOME}/.abacusai/mcp.json`,
      `${HOME}/.abacusai/desktop/agent-config-code.json`,
      `${HOME}/.abacusai/desktop/mcp-cowork.json`,
    ]);
    expect(inst.skillsDirs).toEqual([`${HOME}/.abacusai/skills`]);
    expect(inst.models).toEqual([
      { id: 'claude-sonnet-5', provider: 'abacus', via: 'model' },
      { id: 'qwen3', provider: 'ollama', via: 'smallModel' },
    ]);
  });

  it('detects desktop-only installs from the Electron user-data dir', async () => {
    vi.spyOn(process, 'cwd').mockReturnValue('/somewhere/else');
    const fs = makeFs({ [`${HOME}/.config/AbacusAI Desktop/device.json`]: '{}' });
    const installs = await abacusAdapter.detect({ fs });
    expect(installs).toHaveLength(1);
    expect(installs[0].configFiles).toEqual([]);
  });

  it('records the desktop app bundle on macOS', async () => {
    vi.spyOn(process, 'cwd').mockReturnValue('/somewhere/else');
    const fs = makeFs({
      [`${HOME}/Library/Application Support/AbacusAI Desktop/device.json`]: '{}',
      '/Applications/AbacusAI Desktop.app/': '',
    }, 'darwin');
    const [inst] = await abacusAdapter.detect({ fs });
    expect(inst.appBundle).toBe('/Applications/AbacusAI Desktop.app');
  });

  it('adds a project installation for <cwd>/.abacusai and skips it when run from $HOME', async () => {
    vi.spyOn(process, 'cwd').mockReturnValue('/work/app');
    const fs = makeFs({
      [`${HOME}/.abacusai/config.json`]: '{}',
      '/work/app/.abacusai/config.json': '{ "permissionMode": "unsupervised" }',
      '/work/app/.agents/skills/deploy/SKILL.md': '# deploy',
    });
    const installs = await abacusAdapter.detect({ fs });
    const project = installs.find(i => i.profile === 'project')!;
    expect(project.agentName).toBe('project:app');
    expect(project.installDir).toBe('/work/app/.abacusai');
    expect(project.configFiles.map(c => c.filePath)).toEqual(['/work/app/.abacusai/config.json']);
    expect(project.skillsDirs).toEqual(['/work/app/.agents/skills']);

    vi.spyOn(process, 'cwd').mockReturnValue(HOME);
    const fromHome = await abacusAdapter.detect({ fs: makeFs({ [`${HOME}/.abacusai/config.json`]: '{}' }) });
    expect(fromHome.filter(i => i.profile === 'project')).toHaveLength(0);
  });

  it('ignores unparseable and non-object configs', async () => {
    vi.spyOn(process, 'cwd').mockReturnValue('/somewhere/else');
    const fs = makeFs({ [`${HOME}/.abacusai/config.json`]: '{ broken', [`${HOME}/.abacusai/mcp.json`]: '[]' });
    const [inst] = await abacusAdapter.detect({ fs });
    expect(inst.configFiles).toEqual([]);
  });

  it('never executes the npm shim (it installs on run) — versions it from package.json', async () => {
    vi.spyOn(process, 'cwd').mockReturnValue('/somewhere/else');
    const nvmBin = `${HOME}/.nvm/versions/node/v22.0.0/bin/abacusai`;
    const shim = `${HOME}/.nvm/versions/node/v22.0.0/lib/node_modules/@abacus-ai/cli/scripts/npm-wrapper/shim.cjs`;
    const base = makeFs({
      [`${HOME}/.abacusai/config.json`]: '{}',
      [nvmBin]: '',
      [shim]: '',
      [`${HOME}/.nvm/versions/node/v22.0.0/lib/node_modules/@abacus-ai/cli/package.json`]: '{ "name": "@abacus-ai/cli", "version": "2.10.1" }',
    });
    const exec = vi.fn(async () => ({ exitCode: 0, stdout: 'Abacus.AI CLI version 9.9.9', stderr: '' }));
    const fs = {
      ...base,
      exec,
      execSync: (cmd: string) => (cmd.includes('which') ? nvmBin : (() => { throw new Error('nf'); })()),
      realpath: async (p: string) => (p === nvmBin ? shim : p),
      readdirEntries: async (d: string) => (d === `${HOME}/.nvm/versions/node` ? [{ name: 'v22.0.0', isDirectory: true }] : []),
    } as unknown as FSProvider;

    const [inst] = await abacusAdapter.detect({ fs });
    const all = [inst.cliBinary ? { path: inst.cliBinary, version: inst.version } : undefined, ...(inst.otherInstalls ?? [])].filter(Boolean);
    expect(all).toContainEqual({ path: nvmBin, version: '2.10.1' });
    expect(exec.mock.calls.some(c => String(c[0]).includes('abacusai'))).toBe(false);
  });

  it('reports nothing without a positive signal', async () => {
    vi.spyOn(process, 'cwd').mockReturnValue('/somewhere/else');
    expect(await abacusAdapter.detect({ fs: makeFs({}) })).toEqual([]);
  });

  it('declares a privacy-preserving probe manifest', () => {
    const m = abacusAdapter.getProbeManifest!();
    expect(m.metadataGlobPatterns).toEqual(expect.arrayContaining(['~/.abacusai/keystore.enc*', '~/.abacusai/history.jsonl', '~/.abacusai/projects/**', '~/.abacusai/logs/**']));
    expect([...m.filePaths, ...m.globPatterns].some(p => p.includes('history'))).toBe(false);
    expect(m.filePaths.some(p => p.includes('keystore') || p.includes('projects/'))).toBe(false);
    expect(m.envPrefixes).toEqual(['ABACUS_', 'CODELLM_']);
  });
});
