import { describe, it, expect, vi, afterEach } from 'vitest';
import type { FSProvider } from '../core/fs-provider.js';
import { devinAdapter } from './devin.js';

const HOME = '/home/tester';

/** Files map to contents; a key ending in '/' declares an (empty) directory. */
function makeFs(files: Record<string, string>): FSProvider {
  const paths = new Set<string>();
  for (const key of Object.keys(files)) {
    let p = key.endsWith('/') ? key.slice(0, -1) : key;
    paths.add(p);
    while ((p = p.slice(0, p.lastIndexOf('/'))) && p.length > 0) paths.add(p);
  }
  return {
    platform: 'linux',
    homedir: () => HOME,
    getEnv: () => undefined,
    access: async (p: string) => paths.has(p),
    readFile: async (p: string) => {
      if (!(p in files)) throw new Error(`ENOENT ${p}`);
      return files[p];
    },
    execSync: () => { throw new Error('not found'); },
  } as unknown as FSProvider;
}

describe('Devin adapter — project discovery, hooks file, skills', () => {
  afterEach(() => vi.restoreAllMocks());

  it('walks up from cwd to the repo root and loads .devin/ there, plus hooks.v1.json', async () => {
    vi.spyOn(process, 'cwd').mockReturnValue('/work/app/packages/api');
    const fs = makeFs({
      [`${HOME}/.config/devin/config.json`]: '{}',
      '/work/app/.git/': '',
      '/work/app/.devin/config.json': '{ "requiredPlugins": ["acme/x"] }',
      '/work/app/.devin/hooks.v1.json': '{ "PreToolUse": [{ "matcher": "exec", "hooks": [{ "type": "command", "command": "./audit.sh" }] }] }',
      '/work/app/packages/api/.devin/config.local.json': '{ "permissions": { "allow": ["exec"] } }',
      '/work/app/.devin/skills/deploy/SKILL.md': '# deploy',
    });
    const installs = await devinAdapter.detect({ fs });
    const project = installs.find(i => i.profile === 'project')!;

    expect(project.agentName).toBe('project:app');
    expect(project.installDir).toBe('/work/app/.devin');
    expect(project.configFiles.map(c => c.filePath)).toEqual([
      '/work/app/.devin/config.json',
      '/work/app/.devin/hooks.v1.json',
      '/work/app/packages/api/.devin/config.local.json',
    ]);
    // The standalone hooks file is the hooks object itself
    expect(Object.keys(project.configFiles[1].data.hooks as object)).toEqual(['PreToolUse']);
    expect(project.skillsDirs).toEqual(['/work/app/.devin/skills']);
  });

  it('records user skill roots and does not duplicate them as project skills when run from $HOME', async () => {
    vi.spyOn(process, 'cwd').mockReturnValue(HOME);
    const fs = makeFs({
      [`${HOME}/.config/devin/config.json`]: '{}',
      [`${HOME}/.agents/skills/tool/SKILL.md`]: '# tool',
      [`${HOME}/.config/devin/skills/`]: '',
    });
    const installs = await devinAdapter.detect({ fs });
    expect(installs).toHaveLength(1);
    expect(installs[0].skillsDirs).toEqual([`${HOME}/.config/devin/skills`, `${HOME}/.agents/skills`]);
  });

  it('resolves credential paths against the scanned host, not the scanner', () => {
    const remote = makeFs({});
    expect(devinAdapter.getCredentialPaths!(`${HOME}/.config/devin`, remote))
      .toEqual([`${HOME}/.local/share/devin/credentials.toml`]);
    expect(devinAdapter.getCredentialPaths!('/work/app/.devin', remote)).toEqual([]);
  });
});

