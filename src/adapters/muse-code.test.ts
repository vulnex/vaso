import { describe, it, expect, vi, afterEach } from 'vitest';
import type { FSProvider } from '../core/fs-provider.js';
import { museCodeAdapter, museAuthPath, museConfigDir, museDataDir } from './muse-code.js';

const HOME = '/home/tester';
const LAUNCHER = '#!/usr/bin/env bash\nset -euo pipefail\nlauncher_version="4"\nuser_agent="muse-code/launcher-$launcher_version"\n';

/** Files map to contents; a key ending in '/' declares an (empty) directory. */
function makeFs(files: Record<string, string>, env: Record<string, string> = {}): FSProvider {
  const paths = new Set<string>();
  for (const key of Object.keys(files)) {
    let p = key.endsWith('/') ? key.slice(0, -1) : key;
    paths.add(p);
    while ((p = p.slice(0, p.lastIndexOf('/'))) && p.length > 0) paths.add(p);
  }
  return {
    platform: 'linux',
    kind: 'local',
    homedir: () => HOME,
    getEnv: (k: string) => env[k],
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

describe('Muse Code adapter', () => {
  afterEach(() => vi.restoreAllMocks());

  it('detects the launcher, versions it from .muse-version and loads settings + trust', async () => {
    vi.spyOn(process, 'cwd').mockReturnValue('/somewhere/else');
    const fs = makeFs({
      [`${HOME}/.local/bin/muse`]: LAUNCHER,
      [`${HOME}/.local/bin/.muse-version`]: '1.4.25-R9361.1\n',
      [`${HOME}/.config/muse/settings.json`]: '{ "schema_version": 1, "model": "spark-1.3", "permissions": { "schema_version": 1, "default_profile": ":read-only" } }',
      [`${HOME}/.config/muse/trust.json`]: '{ "schema_version": 1, "projects": {} }',
      [`${HOME}/.config/muse/skills/`]: '',
    });
    const [inst] = await museCodeAdapter.detect({ fs });
    expect(inst.agent).toBe('muse-code');
    expect(inst.version).toBe('1.4.25');
    expect(inst.cliBinary).toBe(`${HOME}/.local/bin/muse`);
    expect(inst.installDir).toBe(`${HOME}/.config/muse`);
    expect(inst.configFiles.map(c => c.filePath)).toEqual([`${HOME}/.config/muse/settings.json`, `${HOME}/.config/muse/trust.json`]);
    expect(inst.skillsDirs).toEqual([`${HOME}/.config/muse/skills`]);
    expect(inst.models).toEqual([{ id: 'spark-1.3', provider: 'meta', via: 'model' }]);
  });

  it('ignores an unrelated program called muse', async () => {
    vi.spyOn(process, 'cwd').mockReturnValue('/somewhere/else');
    const fs = makeFs({ '/usr/local/bin/muse': '#!/usr/bin/env python3\nprint("music")\n' });
    expect(await museCodeAdapter.detect({ fs })).toEqual([]);
  });

  it('detects from the data dir alone (launcher removed)', async () => {
    vi.spyOn(process, 'cwd').mockReturnValue('/somewhere/else');
    const installs = await museCodeAdapter.detect({ fs: makeFs({ [`${HOME}/.local/share/muse/session-index.db`]: 'x' }) });
    expect(installs).toHaveLength(1);
    expect(installs[0].version).toBeUndefined();
  });

  it('honours XDG dirs and MUSE_AUTH_PATH for the scanning user', () => {
    const fs = makeFs({}, { XDG_CONFIG_HOME: '/x/cfg', XDG_DATA_HOME: '/x/data', MUSE_AUTH_PATH: '~/secrets/muse.json' });
    expect(museConfigDir(HOME, fs)).toBe('/x/cfg/muse');
    expect(museDataDir(HOME, fs)).toBe('/x/data/muse');
    expect(museAuthPath(HOME, fs)).toBe(`${HOME}/secrets/muse.json`);
    // Another user's home: their environment is not observable
    expect(museConfigDir('/home/other', fs)).toBe('/home/other/.config/muse');
  });

  it('adds the workspace .mcp.json / .muse/hooks.json / .agents/skills as a project installation', async () => {
    vi.spyOn(process, 'cwd').mockReturnValue('/work/app');
    const fs = makeFs({
      [`${HOME}/.config/muse/settings.json`]: '{}',
      '/work/app/.mcp.json': '{ "mcpServers": {} }',
      '/work/app/.muse/hooks.json': '{ "hooks": {} }',
      '/work/app/.agents/skills/deploy/SKILL.md': '# deploy',
    });
    const installs = await museCodeAdapter.detect({ fs });
    const project = installs.find(i => i.profile === 'project')!;
    expect(project.agentName).toBe('project:app');
    expect(project.installDir).toBe('/work/app/.muse');
    expect(project.configFiles.map(c => c.filePath)).toEqual(['/work/app/.mcp.json', '/work/app/.muse/hooks.json']);
    expect(project.skillsDirs).toEqual(['/work/app/.agents/skills']);
  });

  it('never runs the launcher (it updates and may log in): no version command in the probe manifest', () => {
    const m = museCodeAdapter.getProbeManifest!();
    expect(m.commands?.map(c => c.cmd)).toEqual(['which']);
    expect(m.metadataGlobPatterns).toContain('~/.config/muse/auth.json');
    expect(m.metadataGlobPatterns).toContain('~/.local/share/muse/sessions/**');
  });
});
