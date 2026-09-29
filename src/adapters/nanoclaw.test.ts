import { describe, it, expect, afterEach } from 'vitest';
import { join } from 'node:path';
import { mkdtempSync, mkdirSync, writeFileSync, symlinkSync, rmSync, realpathSync } from 'node:fs';
import { tmpdir } from 'node:os';
import type { ParsedConfig } from '../core/types.js';
import type { ProbeSnapshot } from '../core/snapshot-types.js';
import { SnapshotFSProvider } from '../core/snapshot-fs-provider.js';
import { LocalFSProvider } from '../core/local-fs-provider.js';
import { nanoclawAdapter, isNanoclawCheckout } from './nanoclaw.js';

const HOME = '/home/test';
const PKG = JSON.stringify({ name: 'nanoclaw', version: '2.4.0', bin: { ncl: 'bin/ncl' } });
// Shape written by `setup --step mounts` (upstream setup/mounts.ts)
const ALLOWLIST = JSON.stringify({
  allowedRoots: [{ path: '~', allowReadWrite: true }],
  blockedPatterns: [],
  nonMainReadOnly: false,
}, null, 2);
// Shape written by `setup set-env` (upstream setup/set-env.ts)
const ENV = [
  'ASSISTANT_NAME=Andy',
  'TZ=UTC',
  'NANOCLAW_GATEWAY_PROVIDER=onecli',
  'TELEGRAM_BOT_TOKEN=000000000:fake-token-for-tests',
  'WEBHOOK_PORT=3000',
].join('\n');

type Entry = string | { content?: string; mode?: number };

function snapshot(files: Record<string, Entry>, env: Record<string, string> = {}): SnapshotFSProvider {
  const snap: ProbeSnapshot = {
    version: 1,
    hostname: 'test-host',
    platform: 'linux',
    homedir: HOME,
    timestamp: '2026-09-29T00:00:00Z',
    privilege: { uid: 1000, username: 'test', isRoot: false, sudoAvailable: false, escalated: false, scannedUsers: ['test'], skippedPaths: [] },
    files: Object.fromEntries(Object.entries(files).map(([p, e]) => {
      const entry = typeof e === 'string' ? { content: e } : e;
      return [p, {
        content: entry.content ?? '',
        mode: entry.mode ?? 0o100600,
        exists: true,
        ...(entry.content === undefined ? { contentOmitted: true } : {}),
      }];
    })),
    directories: {},
    commandOutputs: {},
    env,
  };
  return new SnapshotFSProvider(snap);
}

describe('NanoClaw adapter — detection', () => {
  it('returns nothing without a checkout or ~/.config/nanoclaw', async () => {
    const fs = snapshot({ [`${HOME}/.bashrc`]: '' });
    expect(await nanoclawAdapter.detect({ fs })).toEqual([]);
  });

  it('falls back to ~/.config/nanoclaw when only the mounts step has run', async () => {
    const fs = snapshot({ [`${HOME}/.config/nanoclaw/mount-allowlist.json`]: ALLOWLIST });
    const [inst, ...rest] = await nanoclawAdapter.detect({ fs });
    expect(rest).toHaveLength(0);
    expect(inst.installDir).toBe(`${HOME}/.config/nanoclaw`);
    expect(inst.version).toBeUndefined();
    expect(inst.skillsDir).toBeUndefined();
    expect(inst.configFiles.map(c => c.filePath)).toEqual([`${HOME}/.config/nanoclaw/mount-allowlist.json`]);
    expect(inst.configFiles[0].data.allowedRoots).toEqual([{ path: '~', allowReadWrite: true }]);
    expect(nanoclawAdapter.getCredentialPaths!(inst.installDir)).toEqual([]);
  });

  it('detects a ~/nanoclaw checkout: version from package.json, .env + allowlist as configs', async () => {
    const fs = snapshot({
      [`${HOME}/nanoclaw/package.json`]: PKG,
      [`${HOME}/nanoclaw/.env`]: ENV,
      [`${HOME}/.config/nanoclaw/mount-allowlist.json`]: ALLOWLIST,
    });
    const [inst, ...rest] = await nanoclawAdapter.detect({ fs });
    expect(rest).toHaveLength(0);
    expect(inst.installDir).toBe(`${HOME}/nanoclaw`);
    expect(inst.version).toBe('2.4.0');
    expect(inst.skillsDir).toBe(`${HOME}/nanoclaw/container/skills`);
    expect(inst.configFiles.map(c => c.filePath)).toEqual([
      `${HOME}/nanoclaw/.env`,
      `${HOME}/.config/nanoclaw/mount-allowlist.json`,
    ]);
    expect(inst.configFiles[0].format).toBe('env');
    expect(inst.configFiles[0].data.TELEGRAM_BOT_TOKEN).toBeDefined();
    expect(nanoclawAdapter.getCredentialPaths!(inst.installDir)).toEqual([`${HOME}/nanoclaw/.env`]);
  });

  it('finds checkouts under common parents (~/src/nanoclaw-v2)', async () => {
    const fs = snapshot({ [`${HOME}/src/nanoclaw-v2/package.json`]: PKG });
    const insts = await nanoclawAdapter.detect({ fs });
    expect(insts.map(i => i.installDir)).toEqual([`${HOME}/src/nanoclaw-v2`]);
  });

  it('ignores name matches that are not the NanoClaw package', async () => {
    const fs = snapshot({
      [`${HOME}/nanoclaw-notes/package.json`]: JSON.stringify({ name: 'my-notes', version: '1.0.0' }),
      [`${HOME}/nanoclaw-docs/README.md`]: '# notes',
    });
    expect(await nanoclawAdapter.detect({ fs })).toEqual([]);
  });

  it('follows the systemd user unit to a checkout with an unrelated name', async () => {
    const unit = [
      '[Unit]', 'Description=NanoClaw Personal Assistant', '', '[Service]', 'Type=simple',
      `ExecStart=/usr/bin/node ${HOME}/apps/assistant/dist/index.js`,
      `WorkingDirectory=${HOME}/apps/assistant`, 'Restart=always',
    ].join('\n');
    const fs = snapshot({
      [`${HOME}/.config/systemd/user/nanoclaw-v2-ab12cd34.service`]: unit,
      [`${HOME}/apps/assistant/package.json`]: PKG,
    });
    const insts = await nanoclawAdapter.detect({ fs });
    expect(insts.map(i => [i.installDir, i.version])).toEqual([[`${HOME}/apps/assistant`, '2.4.0']]);
  });

  it('follows the launchd plist WorkingDirectory and dedupes with the name scan', async () => {
    const plist = `<?xml version="1.0"?><plist version="1.0"><dict>
    <key>Label</key><string>com.nanoclaw-v2-ab12cd34</string>
    <key>WorkingDirectory</key>
    <string>${HOME}/nanoclaw</string></dict></plist>`;
    const fs = snapshot({
      [`${HOME}/Library/LaunchAgents/com.nanoclaw-v2-ab12cd34.plist`]: plist,
      [`${HOME}/nanoclaw/package.json`]: PKG,
    });
    const insts = await nanoclawAdapter.detect({ fs });
    expect(insts.map(i => i.installDir)).toEqual([`${HOME}/nanoclaw`]);
  });

  it('accepts a unit-named checkout the snapshot did not collect (version unknown)', async () => {
    const fs = snapshot({
      [`${HOME}/.config/systemd/user/nanoclaw-v2-ab12cd34.service`]: `[Service]\nWorkingDirectory=/opt/nanoclaw-box\n`,
    });
    const insts = await nanoclawAdapter.detect({ fs });
    expect(insts.map(i => [i.installDir, i.version])).toEqual([['/opt/nanoclaw-box', undefined]]);
  });

  it('does not treat v1-era files as an install', async () => {
    const fs = snapshot({
      [`${HOME}/.nanoclaw.env`]: 'NANOCLAW_HOME=/opt/x\nNANOCLAW_PORT=9090\n',
      [`${HOME}/.config/nanoclaw/config.json`]: '{}',
    });
    expect(await nanoclawAdapter.detect({ fs })).toEqual([]);
  });
});

describe('NanoClaw adapter — local filesystem', () => {
  let root: string | undefined;
  afterEach(() => {
    if (root) rmSync(root, { recursive: true, force: true });
    root = undefined;
  });

  class HomeFs extends LocalFSProvider {
    constructor(private readonly home: string) { super(); }
    homedir(): string { return this.home; }
  }

  it('resolves the checkout through the ~/.local/bin/ncl symlink', async () => {
    root = realpathSync(mkdtempSync(join(tmpdir(), 'vaso-nc-adapter-')));
    const checkout = join(root, 'opt', 'assistant');
    mkdirSync(join(checkout, 'bin'), { recursive: true });
    writeFileSync(join(checkout, 'package.json'), PKG);
    writeFileSync(join(checkout, 'bin', 'ncl'), '#!/usr/bin/env bash\n');
    const home = join(root, 'home');
    mkdirSync(join(home, '.local', 'bin'), { recursive: true });
    symlinkSync(join(checkout, 'bin', 'ncl'), join(home, '.local', 'bin', 'ncl'));

    const insts = await nanoclawAdapter.detect({ fs: new HomeFs(home) });
    expect(insts.map(i => [i.installDir, i.version])).toEqual([[checkout, '2.4.0']]);
  });
});

describe('NanoClaw adapter — metadata', () => {
  const cfg = (filePath: string, data: Record<string, unknown>): ParsedConfig =>
    ({ raw: '', format: 'env', filePath, data });

  it('reports NANOCLAW_DEFAULT_MODEL under the default provider', async () => {
    const env = cfg(`${HOME}/nanoclaw/.env`, { NANOCLAW_DEFAULT_MODEL: 'claude-sonnet-4-6' });
    expect(await nanoclawAdapter.getModels!([env])).toEqual([{ id: 'claude-sonnet-4-6', provider: 'claude' }]);
    const codex = cfg(`${HOME}/nanoclaw/.env`, { NANOCLAW_DEFAULT_MODEL: 'gpt-5', DEFAULT_AGENT_PROVIDER: 'Codex' });
    expect(await nanoclawAdapter.getModels!([codex])).toEqual([{ id: 'gpt-5', provider: 'codex' }]);
    expect(await nanoclawAdapter.getModels!([cfg(`${HOME}/nanoclaw/.env`, {})])).toEqual([]);
  });

  it('has no gateway (the webhook listener is assessed by NC-004)', () => {
    expect(nanoclawAdapter.getGatewayInfo({})).toBeUndefined();
  });

  it('tells a checkout from the config-dir fallback', () => {
    expect(isNanoclawCheckout(`${HOME}/nanoclaw`)).toBe(true);
    expect(isNanoclawCheckout(`${HOME}/.config/nanoclaw`)).toBe(false);
    expect(nanoclawAdapter.getSkillsDir(`${HOME}/.config/nanoclaw`)).toBeUndefined();
  });

  it('probe manifest ships config + skills, keeps DBs/socket/identity files metadata-only', () => {
    const m = nanoclawAdapter.getProbeManifest!();
    const content = [...m.filePaths, ...m.globPatterns];
    const meta = m.metadataGlobPatterns ?? [];
    expect(m.filePaths).toContain('~/.config/nanoclaw/mount-allowlist.json');
    expect(content).toContain('~/*[nN][aA][nN][oO][cC][lL][aA][wW]*/.env');
    expect(content).toContain('~/*[nN][aA][nN][oO][cC][lL][aA][wW]*/package.json');
    expect(content).toContain('~/*[nN][aA][nN][oO][cC][lL][aA][wW]*/src/channels/index.ts');
    expect(meta).toContain('~/*[nN][aA][nN][oO][cC][lL][aA][wW]*/data/*');
    expect(meta).toContain('~/.config/nanoclaw/*');
    for (const p of content) {
      expect(p).not.toMatch(/\/data\/|v2\.db|device-key|account\.json|registry-auth|\.claude\/skills/);
    }
    for (const g of meta) expect(m.globPatterns).not.toContain(g);
    expect(m.commands).toEqual([]);
  });
});
