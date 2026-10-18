import { describe, it, expect, vi, afterEach } from 'vitest';
import type { FSProvider } from '../core/fs-provider.js';
import type { ScanContext } from '../core/types.js';
import { claudeCodeAdapter, claudeProjectScope } from './claude-code.js';
import { cc001 } from '../checks/claude-code/cc-001-bypass-permissions.js';
import { cc012 } from '../checks/claude-code/cc-012-memory-secret-leak.js';

// Claude Code scopes against an in-memory host: managed settings, the repo
// root when started in a subdirectory, a symlinked $HOME.

const HOME = '/home/tester';
const GH_TOKEN = 'ghp_' + 'Zx9Qw8Er7Ty6Ui5Op4As3Df2Gh1Jk0LzXcVb';

function fakeFs(files: Record<string, string>, opts: { home?: string; links?: Record<string, string> } = {}): FSProvider {
  const links = opts.links ?? {};
  // resolve a path through the (prefix) symlinks
  const resolve = (p: string) => {
    for (const [from, to] of Object.entries(links)) if (p === from || p.startsWith(from + '/')) return to + p.slice(from.length);
    return p;
  };
  const paths = new Set<string>();
  for (const key of Object.keys(files)) {
    let p = key;
    paths.add(p);
    while ((p = p.slice(0, p.lastIndexOf('/'))) && p.length > 0) paths.add(p);
  }
  return {
    kind: 'local',
    platform: 'linux',
    homedir: () => opts.home ?? HOME,
    getEnv: () => undefined,
    access: async (p: string) => paths.has(resolve(p)),
    stat: async (p: string) => {
      const r = resolve(p);
      if (!paths.has(r)) throw Object.assign(new Error(`ENOENT ${p}`), { code: 'ENOENT' });
      return { mode: 0o100600, isFile: () => r in files, isDirectory: () => !(r in files) };
    },
    readFile: async (p: string) => {
      const r = resolve(p);
      if (!(r in files)) throw Object.assign(new Error(`ENOENT ${p}`), { code: 'ENOENT' });
      return files[r];
    },
    readdir: async (p: string) => {
      const r = resolve(p);
      if (!paths.has(r) || r in files) throw Object.assign(new Error(`ENOENT ${p}`), { code: 'ENOENT' });
      return [...paths].filter(x => x.startsWith(r + '/') && !x.slice(r.length + 1).includes('/')).map(x => x.slice(r.length + 1));
    },
    readdirEntries: async () => { throw new Error('ENOENT'); },
    realpath: async (p: string) => resolve(p),
    exec: async () => ({ exitCode: 1, stdout: '', stderr: '' }),
    execSync: () => { throw new Error('no exec'); },
  } as unknown as FSProvider;
}

afterEach(() => vi.restoreAllMocks());

describe('Claude Code managed settings', () => {
  const managed = {
    '/etc/claude-code/managed-settings.json': JSON.stringify({ permissions: { deny: ['Bash(rm:*)'] } }),
    '/etc/claude-code/managed-settings.d/20-security.json': JSON.stringify({ permissions: { disableBypassPermissionsMode: 'disable' } }),
    '/etc/claude-code/managed-settings.d/10-telemetry.json': '{}',
    '/etc/claude-code/managed-settings.d/.hidden.json': '{}',
  };

  it('loads managed-settings.json then the drop-ins alphabetically into the user install', async () => {
    vi.spyOn(process, 'cwd').mockReturnValue('/nowhere');
    const fs = fakeFs({ [`${HOME}/.claude/settings.json`]: '{}', ...managed });
    const [inst] = await claudeCodeAdapter.detect({ fs });
    expect(inst.configFiles.map(c => c.filePath)).toEqual([
      `${HOME}/.claude/settings.json`,
      '/etc/claude-code/managed-settings.json',
      '/etc/claude-code/managed-settings.d/10-telemetry.json',
      '/etc/claude-code/managed-settings.d/20-security.json',
    ]);
  });

  it('collects managed settings in remote scans', () => {
    const m = claudeCodeAdapter.getProbeManifest!();
    expect(m.systemPaths).toContain('/etc/claude-code/managed-settings.json');
    expect(m.globPatterns).toContain('/etc/claude-code/managed-settings.d/*.json');
  });
});

describe('CC-001 and disableBypassPermissionsMode', () => {
  function ctx(configs: Array<[string, Record<string, unknown>]>, files: Record<string, string> = {}, profile?: string): ScanContext {
    return {
      installation: { agent: 'claude-code', installDir: profile ? '/repo/.claude' : `${HOME}/.claude`, configFiles: [], profile },
      configs: configs.map(([filePath, data]) => ({ raw: '', format: 'json', filePath, data })),
      platform: 'linux',
      fs: fakeFs(files),
    };
  }

  it('bypassPermissions is critical without the lock', async () => {
    const r = await cc001.run(ctx([[`${HOME}/.claude/settings.json`, { permissions: { defaultMode: 'bypassPermissions' } }]]));
    expect(r.passed).toBe(false);
    expect(r.severity).toBe('critical');
  });

  it.each(['disable', true])('a lock (%s) in any loaded file makes it inactive', async (value) => {
    const r = await cc001.run(ctx([
      [`${HOME}/.claude/settings.json`, { permissions: { defaultMode: 'bypassPermissions' } }],
      ['/etc/claude-code/managed-settings.json', { permissions: { disableBypassPermissionsMode: value } }],
    ]));
    expect(r.passed).toBe(false);
    expect(r.severity).toBe('info');
    expect(r.evidence?.every(e => e.mitigated)).toBe(true);
  });

  it('a project install counts the lock in user or managed settings', async () => {
    const r = await cc001.run(ctx(
      [['/repo/.claude/settings.json', { dangerouslySkipPermissions: true }]],
      { '/etc/claude-code/managed-settings.d/50.json': JSON.stringify({ permissions: { disableBypassPermissionsMode: 'disable' } }) },
      'project',
    ));
    expect(r.severity).toBe('info');
  });
});

describe('Claude Code project scope from a subdirectory', () => {
  const files = {
    '/w/repo/.git/HEAD': 'ref: refs/heads/main',
    '/w/repo/CLAUDE.md': `token ${GH_TOKEN}`,
    '/w/repo/.claude/settings.local.json': JSON.stringify({ permissions: { allow: ['Bash'] } }),
    '/w/repo/pkg/app/.claude/settings.json': JSON.stringify({ permissions: { allow: ['Read'] } }),
  };

  it('walks to the repository root for memory and the local settings file', async () => {
    const scope = await claudeProjectScope('/w/repo/pkg/app', fakeFs(files));
    expect(scope.root).toBe('/w/repo');
    expect(scope.localSettingsDir).toBe('/w/repo/.claude');
    expect(scope.memoryPaths).toEqual(expect.arrayContaining(['/w/repo/pkg/app/CLAUDE.md', '/w/repo/pkg/CLAUDE.md', '/w/repo/CLAUDE.md', '/w/repo/CLAUDE.local.md']));
    expect(scope.memoryPaths).not.toContain('/w/CLAUDE.md');
  });

  it('outside a repo only the working directory counts; a root at $HOME keeps the local file in place', async () => {
    expect((await claudeProjectScope('/w/x', fakeFs({ '/w/x/CLAUDE.md': '' }))).memoryPaths).not.toContain('/w/CLAUDE.md');
    const homeRepo = await claudeProjectScope(`${HOME}/sub`, fakeFs({ [`${HOME}/.git/HEAD`]: '' }));
    expect(homeRepo.localSettingsDir).toBeUndefined();
  });

  it('the project install loads the root settings.local.json and CC-012 reads the root CLAUDE.md', async () => {
    vi.spyOn(process, 'cwd').mockReturnValue('/w/repo/pkg/app');
    const fs = fakeFs(files);
    const project = (await claudeCodeAdapter.detect({ fs })).find(i => i.profile === 'project')!;
    expect(project.configFiles.map(c => c.filePath)).toEqual([
      '/w/repo/pkg/app/.claude/settings.json',
      '/w/repo/.claude/settings.local.json',
    ]);
    const r = await cc012.run({ installation: project, configs: project.configFiles, platform: 'linux', fs });
    expect(r.passed).toBe(false);
    expect(r.evidence?.[0].file).toBe('/w/repo/CLAUDE.md');
  });
});

describe('symlinked $HOME', () => {
  it('scanning from home does not report the user dir again as a project', async () => {
    // $HOME = /home/link → /data/real; the working directory is the real path
    const files = {
      '/data/real/.claude/settings.json': '{}',
      '/data/real/.claude/CLAUDE.md': 'notes',
      '/data/real/CLAUDE.md': 'notes',
    };
    vi.spyOn(process, 'cwd').mockReturnValue('/data/real');
    const fs = fakeFs(files, { home: '/home/link', links: { '/home/link': '/data/real' } });
    const installs = await claudeCodeAdapter.detect({ fs });
    expect(installs.filter(i => i.profile === 'project')).toEqual([]);
  });
});
