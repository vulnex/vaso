import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, mkdir, writeFile, rm, realpath } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { LocalFSProvider } from '../core/local-fs-provider.js';
import type { FSProvider } from '../core/fs-provider.js';
import { openclawAdapter, openclawEnvPaths } from './openclaw.js';

/**
 * Where OpenClaw runs from — each case verified with `openclaw config file`
 * 2026.9.4 under the same fixture HOME.
 */

let home: string;

function fsFor(env: Record<string, string> = {}): FSProvider {
  const base = new LocalFSProvider();
  return Object.assign(Object.create(base) as FSProvider, {
    homedir: () => home,
    getEnv: (k: string) => env[k],
    // no agent CLI on the test host's PATH
    execSync: () => { throw new Error('not found'); },
  });
}

async function put(rel: string, content = '{ gateway: { mode: "local" } }'): Promise<void> {
  const p = join(home, rel);
  await mkdir(join(p, '..'), { recursive: true });
  await writeFile(p, content);
}

async function dirs(env: Record<string, string> = {}) {
  const found = await openclawAdapter.detect({ fs: fsFor(env) });
  return found.filter(i => !i.agentName && i.installDir !== '/etc/openclaw')
    .map(i => ({ dir: i.installDir.slice(home.length + 1), profile: i.profile, configs: i.configFiles.map(c => c.filePath.slice(home.length + 1)) }));
}

beforeEach(async () => {
  home = await realpath(await mkdtemp(join(tmpdir(), 'vaso-oc-loc-')));
});

afterEach(async () => {
  await rm(home, { recursive: true, force: true });
});

describe('OpenClaw state directories', () => {
  it('scans ~/.openclaw and not the pre-rename dirs beside it (OpenClaw never reads them then)', async () => {
    await put('.openclaw/openclaw.json');
    await put('.clawdbot/openclaw.json', '{ gateway: { bind: "lan", auth: { mode: "none" } } }');
    await put('.moltbot/openclaw.json', '{ gateway: { bind: "lan", auth: { mode: "none" } } }');
    expect(await dirs()).toEqual([{ dir: '.openclaw', profile: undefined, configs: ['.openclaw/openclaw.json'] }]);
  });

  it('runs from ~/.clawdbot while ~/.openclaw has no config, and reads the legacy clawdbot.json name', async () => {
    await mkdir(join(home, '.openclaw'));
    await put('.clawdbot/clawdbot.json', '{ gateway: { bind: "lan", auth: { mode: "none" } } }');
    const found = await openclawAdapter.detect({ fs: fsFor() });
    const live = found.filter(i => i.installDir !== '/etc/openclaw');
    expect(live.map(i => i.installDir)).toEqual([join(home, '.clawdbot')]);
    expect(live[0].gateway?.host).toBe('0.0.0.0');
  });

  it('prefers ~/.openclaw/clawdbot.json over ~/.clawdbot', async () => {
    await put('.openclaw/clawdbot.json');
    await put('.clawdbot/openclaw.json');
    expect((await dirs()).map(d => d.configs)).toEqual([['.openclaw/clawdbot.json']]);
  });

  it('openclaw.json wins over clawdbot.json in the same dir', async () => {
    await put('.openclaw/openclaw.json');
    await put('.openclaw/clawdbot.json');
    expect((await dirs()).map(d => d.configs)).toEqual([['.openclaw/openclaw.json']]);
  });

  it('never runs from ~/.moltbot', async () => {
    await put('.moltbot/openclaw.json');
    expect(await dirs()).toEqual([]);
  });

  it('discovers every --profile dir as its own installation', async () => {
    await put('.openclaw/openclaw.json');
    await put('.openclaw-ops/openclaw.json', '{ gateway: { bind: "lan" } }');
    await put('.openclaw-default/openclaw.json'); // not a profile dir: --profile default is ~/.openclaw
    expect(await dirs()).toEqual([
      { dir: '.openclaw', profile: undefined, configs: ['.openclaw/openclaw.json'] },
      { dir: '.openclaw-ops', profile: 'ops', configs: ['.openclaw-ops/openclaw.json'] },
    ]);
  });

  it('OPENCLAW_STATE_DIR is the only default state dir — a stale ~/.openclaw is not scanned', async () => {
    await put('.openclaw/openclaw.json', '{ gateway: { bind: "lan" } }');
    await put('state/openclaw.json');
    expect(await dirs({ OPENCLAW_STATE_DIR: join(home, 'state') })).toEqual([
      { dir: 'state', profile: undefined, configs: ['state/openclaw.json'] },
    ]);
  });

  it('expands ~ in OPENCLAW_HOME against the OS home, and in OPENCLAW_STATE_DIR / OPENCLAW_CONFIG_PATH against OPENCLAW_HOME', async () => {
    expect(openclawEnvPaths(home, fsFor({ OPENCLAW_HOME: '~/oh', OPENCLAW_STATE_DIR: '~/st', OPENCLAW_CONFIG_PATH: '~/c.json' })))
      .toEqual({ home: join(home, 'oh'), stateDir: join(home, 'oh/st'), configPath: join(home, 'oh/c.json') });
    await put('oc-state/openclaw.json');
    expect((await dirs({ OPENCLAW_STATE_DIR: '~/oc-state' })).map(d => d.dir)).toEqual(['oc-state']);
    await put('oh/.openclaw/openclaw.json');
    expect((await dirs({ OPENCLAW_HOME: '~/oh' })).map(d => d.dir)).toEqual(['oh/.openclaw']);
  });

  it('applies the variables to the scanning user only', () => {
    expect(openclawEnvPaths('/home/other', fsFor({ OPENCLAW_HOME: '/srv/oc' })).home).toBe('/home/other');
  });
});

describe('/etc/openclaw', () => {
  // No OpenClaw release (clawdbot 2026.1.4 – openclaw 2026.9.4) reads it
  it('is not scanned as an installation, even with an openclaw.json in it', async () => {
    await put('.openclaw/openclaw.json');
    await put('etc-openclaw/openclaw.json', '{ gateway: { bind: "lan", auth: { mode: "none" } } }');
    const base = fsFor();
    const map = (p: string) => (p === '/etc/openclaw' || p.startsWith('/etc/openclaw/') ? join(home, 'etc-openclaw', p.slice('/etc/openclaw'.length)) : p);
    const fs = Object.assign(Object.create(base) as FSProvider, {
      access: (p: string) => base.access(map(p)),
      stat: (p: string) => base.stat(map(p)),
      readFile: (p: string) => base.readFile(map(p)),
      readdirEntries: (p: string, o?: { recursive?: boolean }) => base.readdirEntries(map(p), o),
    });
    const found = await openclawAdapter.detect({ fs });
    expect(found.map(i => i.installDir)).toEqual([join(home, '.openclaw')]);
    expect(found.flatMap(i => i.configFiles.map(c => c.filePath)).some(f => f.startsWith('/etc/openclaw'))).toBe(false);
    expect(openclawAdapter.getConfigPaths().some(p => p.startsWith('/etc/openclaw'))).toBe(false);
  });

  it('declares the main config (gateway token, provider keys) as a credential path', () => {
    const fs = fsFor({ OPENCLAW_CONFIG_PATH: '~/cfg/oc.json' });
    const paths = openclawAdapter.getCredentialPaths!(join(home, '.openclaw'), fs);
    expect(paths).toEqual(expect.arrayContaining([join(home, '.openclaw', 'openclaw.json'), join(home, '.openclaw', 'clawdbot.json'), join(home, 'cfg', 'oc.json')]));
    // a --profile dir reads its own openclaw.json, never OPENCLAW_CONFIG_PATH
    expect(openclawAdapter.getCredentialPaths!(join(home, '.openclaw-work'), fs)).not.toContain(join(home, 'cfg', 'oc.json'));
  });
});
