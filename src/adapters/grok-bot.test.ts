import { describe, it, expect } from 'vitest';
import type { FSProvider } from '../core/fs-provider.js';
import { grokBotAdapter, grokBotDataRoot, grokBotHome, grokBotUserDataDir } from './grok-bot.js';

const HOME = '/home/tester';

/** Files map to contents; a key ending in '/' declares an (empty) directory. */
function makeFs(files: Record<string, string>, opts: { platform?: NodeJS.Platform; env?: Record<string, string> } = {}): FSProvider {
  const paths = new Set<string>();
  for (const key of Object.keys(files)) {
    let p = key.endsWith('/') ? key.slice(0, -1) : key;
    paths.add(p);
    while ((p = p.slice(0, p.lastIndexOf('/'))) && p.length > 0) paths.add(p);
  }
  const env = opts.env ?? {};
  return {
    platform: opts.platform ?? 'linux',
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

describe('Grok Bot adapter', () => {
  it('detects ~/.grokbot, loads settings.json and reads the version from desktop-status.json', async () => {
    const fs = makeFs({
      [`${HOME}/.grokbot/settings.json`]: '{ "version": 1, "localToolPermission": "ask" }',
      [`${HOME}/.config/Grok Bot/desktop-status.json`]: '{ "appVersion": "0.71.2", "pid": 1 }',
      '/opt/Grok Bot/grok-bot': '',
    });
    const [inst] = await grokBotAdapter.detect({ fs });
    expect(inst.agent).toBe('grok-bot');
    expect(inst.installDir).toBe(`${HOME}/.grokbot`);
    expect(inst.version).toBe('0.71.2');
    expect(inst.appBundle).toBe('/opt/Grok Bot');
    expect(inst.configFiles.map(c => c.filePath)).toEqual([`${HOME}/.grokbot/settings.json`]);
  });

  it('detects nothing without a data root, user data or the app', async () => {
    expect(await grokBotAdapter.detect({ fs: makeFs({ [`${HOME}/.cursor/mcp.json`]: '{}' }) })).toEqual([]);
  });

  it('detects an installed app that was never launched', async () => {
    const [inst] = await grokBotAdapter.detect({ fs: makeFs({ '/opt/Grok Bot/grok-bot': '' }) });
    expect(inst.configFiles).toEqual([]);
    expect(inst.version).toBeUndefined();
  });

  it('honours SAND_DATA_ROOT and SAND_USER_DATA_DIR like the app', async () => {
    const env = { SAND_DATA_ROOT: '/srv/grok', SAND_USER_DATA_DIR: '/srv/ud' };
    const fs = makeFs({}, { env });
    expect(await grokBotDataRoot(HOME, fs)).toBe('/srv/grok');
    expect(grokBotUserDataDir(HOME, fs)).toBe('/srv/ud');
    expect(await grokBotDataRoot(HOME, makeFs({}, { env: { SAND_USER_DATA_DIR: '/srv/ud' } }))).toBe('/srv/ud/sand-data');
    // Relative values are ignored, and other users' homes never take the scanner's env
    expect(await grokBotDataRoot(HOME, makeFs({}, { env: { SAND_DATA_ROOT: 'rel' } }))).toBe(`${HOME}/.grokbot`);
    expect(await grokBotDataRoot('/home/other', fs)).toBe('/home/other/.grokbot');
  });

  it('falls back to the pre-rename ~/.cursor/sand data root', async () => {
    const fs = makeFs({ [`${HOME}/.cursor/sand/settings.json`]: '{ "version": 1 }' });
    expect(await grokBotDataRoot(HOME, fs)).toBe(`${HOME}/.cursor/sand`);
    expect(grokBotHome(`${HOME}/.cursor/sand`, fs)).toBe(HOME);
  });

  it('keeps the legacy root while a stray ~/.grokbot has no migration marker (dt15 Grok Bot B7)', async () => {
    const stray = makeFs({ [`${HOME}/.grokbot/notes.txt`]: 'x', [`${HOME}/.cursor/sand/settings.json`]: '{}' });
    expect(await grokBotDataRoot(HOME, stray)).toBe(`${HOME}/.cursor/sand`);
    const migrated = makeFs({ [`${HOME}/.grokbot/.grokbot-data-root-v1`]: '{"version":1}', [`${HOME}/.cursor/sand/settings.json`]: '{}' });
    expect(await grokBotDataRoot(HOME, migrated)).toBe(`${HOME}/.grokbot`);
  });

  it('a relocated root named .grokbot outside $HOME still belongs to the scanning user (dt15 Grok Bot B1)', () => {
    const fs = makeFs({}, { env: { SAND_DATA_ROOT: '/data/.grokbot' } });
    expect(grokBotHome('/data/.grokbot', fs)).toBe(HOME);
    expect(grokBotHome('/home/other/.grokbot', fs)).toBe('/home/other');
  });

  it('uses per-OS user-data dirs', () => {
    expect(grokBotUserDataDir(HOME, makeFs({}, { platform: 'darwin' }))).toBe(`${HOME}/Library/Application Support/Grok Bot`);
    expect(grokBotUserDataDir(HOME, makeFs({}))).toBe(`${HOME}/.config/Grok Bot`);
    expect(grokBotUserDataDir(HOME, makeFs({}, { env: { XDG_CONFIG_HOME: '/x' } }))).toBe('/x/Grok Bot');
  });

  it('declares credential stores in both the data root and user data', () => {
    const paths = grokBotAdapter.getCredentialPaths!(`${HOME}/.grokbot`, makeFs({}));
    expect(paths).toEqual(expect.arrayContaining([
      `${HOME}/.grokbot/local-exec-daemon-credential.json`,
      `${HOME}/.config/Grok Bot/sand-secrets.json`,
      `${HOME}/.config/Grok Bot/user-secrets.json`,
    ]));
  });

  it('never ships secret stores or contact lists with content, nor secret env values', () => {
    const m = grokBotAdapter.getProbeManifest!();
    const content = [...m.filePaths, ...m.globPatterns];
    for (const secret of ['sand-secrets.json', 'user-secrets.json', 'local-exec-daemon-credential.json', 'local-tool-approvals.json', 'local-tool-standing-grants.v1.json', 'Cookies']) {
      expect(content.some(p => p.endsWith(secret)), secret).toBe(false);
      expect(m.metadataGlobPatterns?.some(p => p.endsWith(secret)), secret).toBe(true);
    }
    expect(m.envPrefixes).not.toContain('SAND_');
    expect(m.envPrefixes.some(p => /BEARER|TOKEN|PASSWORD|KEY/.test(p))).toBe(false);
  });
});
