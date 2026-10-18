import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { mkdirSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import type { ScanContext, ParsedConfig, AgentInstallation } from '../../core/types.js';
import type { FSProvider } from '../../core/fs-provider.js';
import { LocalFSProvider } from '../../core/local-fs-provider.js';
import { grokBotChecks } from './index.js';
import { effectivePermission } from './shared.js';

const HOME = '/home/test';
const ROOT = `${HOME}/.grokbot`;
const UD = `${HOME}/.config/Grok Bot`;
const SETTINGS = `${ROOT}/settings.json`;

function cfg(data: Record<string, unknown>, filePath = SETTINGS): ParsedConfig {
  return { raw: JSON.stringify(data), format: 'json', filePath, data };
}

interface FsOpts {
  files?: Record<string, string>;
  modes?: Record<string, number>;
  env?: Record<string, string>;
  platform?: NodeJS.Platform;
}

function makeFs({ files = {}, modes = {}, env = {}, platform = 'linux' }: FsOpts = {}): FSProvider {
  const exists = (p: string) => p in files || p in modes;
  return {
    platform,
    homedir: () => HOME,
    getEnv: (k: string) => env[k],
    access: vi.fn(async (p: string) => exists(p)),
    readFile: vi.fn(async (p: string) => {
      if (!(p in files)) throw new Error(`ENOENT ${p}`);
      return files[p];
    }),
    stat: vi.fn(async (p: string) => {
      if (!(p in modes)) throw new Error(`ENOENT ${p}`);
      return { mode: modes[p], isFile: () => true, isDirectory: () => false };
    }),
  } as unknown as FSProvider;
}

function ctx(configs: ParsedConfig[], fs: FSProvider = makeFs()): ScanContext {
  const installation: AgentInstallation = { agent: 'grok-bot', installDir: ROOT, configFiles: configs };
  return { installation, configs, platform: fs.platform, fs };
}

const check = (id: string) => grokBotChecks.find(c => c.id === id)!;
// Ancestors open to everyone, so permission findings stay live
const OPEN_PARENTS = { [HOME]: 0o755, [`${HOME}/.config`]: 0o755, '/home': 0o755, '/': 0o755 };

describe('Grok Bot checks', () => {
  it('exports 13 coding-agent checks scoped to grok-bot', () => {
    expect(grokBotChecks).toHaveLength(13);
    for (const c of grokBotChecks) {
      expect(c.id).toMatch(/^GB-0(0[1-9]|1[0-3])$/);
      expect(c.category).toBe('coding-agent');
      expect(c.supportedAgents).toEqual(['grok-bot']);
    }
  });

  it('effective permission is the stricter of choice and ceiling, default ask', () => {
    expect(effectivePermission(undefined, undefined)).toBe('ask');
    expect(effectivePermission('always', undefined)).toBe('always');
    expect(effectivePermission('always', 'ask')).toBe('ask');
    expect(effectivePermission('ask', 'always')).toBe('ask');
    expect(effectivePermission('always', 'never')).toBe('never');
    expect(effectivePermission('bogus', undefined)).toBe('ask');
  });
});

describe('GB-001 local execution always allowed', () => {
  it('passes on the defaults (no settings, or "ask")', async () => {
    expect((await check('GB-001').run(ctx([]))).passed).toBe(true);
    expect((await check('GB-001').run(ctx([cfg({ localToolPermission: 'ask' })])))).toMatchObject({ passed: true });
  });

  it('is critical and fixable for "always" without a ceiling — active and parked accounts', async () => {
    const r = await check('GB-001').run(ctx([cfg({
      activeAccountScope: 'a'.repeat(64),
      localToolPermission: 'always',
      accountScopes: { ['b'.repeat(64)]: { localToolPermission: 'always' }, ['a'.repeat(64)]: { localToolPermission: 'never' } },
    })]));
    expect(r.passed).toBe(false);
    expect(r.severity).toBe('critical');
    expect(r.fixable).toBe(true);
    expect(r.evidence).toHaveLength(2);
    expect(r.evidence![1].snippet).toContain(`accountScopes.${'b'.repeat(64)}.localToolPermission`);
  });

  it('is a warning for a parked account only — it takes effect after switching (dt15 Grok Bot B4)', async () => {
    const r = await check('GB-001').run(ctx([cfg({ localToolPermission: 'ask', accountScopes: { ['b'.repeat(64)]: { localToolPermission: 'always' } } })]));
    expect(r).toMatchObject({ passed: false, severity: 'warning', fixable: true });
  });

  it('evaluates the defaults when the app would reject settings.json (dt15 Grok Bot B8)', async () => {
    expect((await check('GB-001').run(ctx([cfg({ version: 2, localToolPermission: 'always' })]))).passed).toBe(true);
    expect((await check('GB-001').run(ctx([cfg({ localToolPermission: 'always', egressTunnelEnabled: 'yes' })]))).passed).toBe(true);
  });

  it('is info when an admin ceiling caps it, and for other machines set to always', async () => {
    const r = await check('GB-001').run(ctx([cfg({
      localToolPermission: 'always', localToolPermissionCeiling: 'ask',
      localToolPermissionByMachineId: { m1: 'always', m2: 'ask' },
    })]));
    expect(r.passed).toBe(false);
    expect(r.severity).toBe('info');
    expect(r.fixable).toBe(false);
  });

  describe('fix', () => {
    let dir: string;
    beforeEach(() => {
      dir = join(realpathSync(process.env.HOME!), '.grokbot');
      mkdirSync(dir, { recursive: true });
    });
    afterEach(() => rmSync(dir, { recursive: true, force: true }));

    it('writes "ask" for every account that allows always, keeping other keys', async () => {
      const file = join(dir, 'settings.json');
      const data = { version: 1, localToolPermission: 'always', egressTunnelEnabled: false, accountScopes: { [`${'c'.repeat(64)}`]: { localToolPermission: 'always' } } };
      writeFileSync(file, JSON.stringify(data, null, 2), { mode: 0o600 });
      const fs = new LocalFSProvider();
      const installation: AgentInstallation = { agent: 'grok-bot', installDir: dir, configFiles: [] };
      const res = await check('GB-001').fix!({ installation, configs: [cfg(data, file)], platform: fs.platform, fs });
      expect(res.applied).toBe(true);
      const after = JSON.parse(readFileSync(file, 'utf-8'));
      expect(after.localToolPermission).toBe('ask');
      expect(after.accountScopes['c'.repeat(64)].localToolPermission).toBe('ask');
      expect(after.egressTunnelEnabled).toBe(false);
      expect(after.version).toBe(1);
    });

    it('fixes an account scope whose key contains a dot in place (no split "dot" → "ted" object)', async () => {
      const file = join(dir, 'settings.json');
      const data = { version: 1, activeAccountScope: 'act', localToolPermission: 'ask', accountScopes: { 'dot.ted': { localToolPermission: 'always' } } };
      writeFileSync(file, JSON.stringify(data, null, 2), { mode: 0o600 });
      const fs = new LocalFSProvider();
      const installation: AgentInstallation = { agent: 'grok-bot', installDir: dir, configFiles: [] };
      const r = await check('GB-001').run(ctx([cfg(data, file)]));
      expect(r.passed).toBe(false);
      expect(r.evidence![0].snippet).toContain('accountScopes."dot.ted".localToolPermission');
      const res = await check('GB-001').fix!({ installation, configs: [cfg(data, file)], platform: fs.platform, fs });
      expect(res.applied).toBe(true);
      const after = JSON.parse(readFileSync(file, 'utf-8'));
      expect(after.accountScopes).toEqual({ 'dot.ted': { localToolPermission: 'ask' } });
    });
  });
});

describe('GB-002 / GB-003 approvals and auto-review', () => {
  it('GB-002 warns on write tools always allowed, info for reads only', async () => {
    const r = await check('GB-002').run(ctx([cfg({ toolPermissions: { scopes: {
      'mcp:gmail': { writes: 'always_allow', reads: 'always_allow' },
      'mcp:slack': { tools: { send_message: 'always_allow', search: 'needs_approval' } },
    } } })]));
    expect(r.passed).toBe(false);
    expect(r.severity).toBe('warning');
    expect(r.evidence).toHaveLength(3);
    const readsOnly = await check('GB-002').run(ctx([cfg({ toolPermissions: { scopes: { 'mcp:x': { reads: 'always_allow' } } } })]));
    expect(readsOnly.severity).toBe('info');
  });

  it('GB-003 warns when auto-review is off and lists allow rules as info', async () => {
    const off = await check('GB-003').run(ctx([cfg({ autoReviewInstructions: { isEnabled: false, allowInstructions: [] } })]));
    expect(off).toMatchObject({ passed: false, severity: 'warning' });
    const rules = await check('GB-003').run(ctx([cfg({ autoReviewInstructions: { isEnabled: true, allowInstructions: ['run any git command'] } })]));
    expect(rules).toMatchObject({ passed: false, severity: 'info' });
    expect((await check('GB-003').run(ctx([cfg({ autoReviewInstructions: { isEnabled: true } })]))).passed).toBe(true);
  });
});

describe('GB-004 standing approvals', () => {
  const GRANTS = `${ROOT}/local-tool-standing-grants.v1.json`;
  const grants = JSON.stringify({ version: 1, grants: [
    { scope: 'action', action: 'send-imessage', accountScope: 'x', grantedAtMs: 1 },
    { scope: 'subject', action: 'send-imessage', recipient: '+15550100', recipientName: 'Alice', accountScope: 'x', grantedAtMs: 1 },
  ] });

  it('warns on an action-wide grant and never quotes recipients', async () => {
    const r = await check('GB-004').run(ctx([cfg({ messagesEnabled: true })], makeFs({ files: { [GRANTS]: grants } })));
    expect(r).toMatchObject({ passed: false, severity: 'warning' });
    expect(JSON.stringify(r.evidence)).not.toMatch(/Alice|15550100/);
  });

  it('downgrades when local execution is capped or refused', async () => {
    const r = await check('GB-004').run(ctx([cfg({ messagesEnabled: true, localToolPermissionCeiling: 'ask' })], makeFs({ files: { [GRANTS]: grants } })));
    expect(r.severity).toBe('info');
  });

  it('ignores grants the daemon never honours (dt15 Grok Bot B5)', async () => {
    const ignored = JSON.stringify({ version: 1, grants: [
      { scope: 'action', action: 'send-imessage', accountScope: 'x', grantedAtMs: 1 }, // Messages off
      { scope: 'action', action: 'run-command', accountScope: 'x', grantedAtMs: 1 }, // global action
      { scope: 'action', action: 'use-app' }, // malformed: no accountScope/grantedAtMs
    ] });
    expect((await check('GB-004').run(ctx([cfg({ messagesEnabled: false })], makeFs({ files: { [GRANTS]: ignored } })))).passed).toBe(true);
    const v2 = JSON.stringify({ version: 2, grants: [{ scope: 'action', action: 'use-app', accountScope: 'x', grantedAtMs: 1 }] });
    expect((await check('GB-004').run(ctx([], makeFs({ files: { [GRANTS]: v2 } })))).passed).toBe(true);
    const app = JSON.stringify({ version: 1, grants: [{ scope: 'action', action: 'use-app', accountScope: 'x', grantedAtMs: 1 }] });
    expect(await check('GB-004').run(ctx([], makeFs({ files: { [GRANTS]: app } })))).toMatchObject({ passed: false, severity: 'warning' });
  });

  it('passes when the file is absent, and says so when content was not collected', async () => {
    expect((await check('GB-004').run(ctx([]))).passed).toBe(true);
    const r = await check('GB-004').run(ctx([], makeFs({ modes: { [GRANTS]: 0o600 } })));
    expect(r.passed).toBe(true);
    expect(r.message).toContain('not inspected');
  });
});

describe('GB-005 egress tunnel', () => {
  it('passes by default, warns when on, critical with private targets', async () => {
    expect((await check('GB-005').run(ctx([cfg({ egressTunnelEnabled: false })]))).passed).toBe(true);
    expect(await check('GB-005').run(ctx([cfg({ egressTunnelEnabled: true })]))).toMatchObject({ passed: false, severity: 'warning' });
    // The settings tunnel never reaches private targets — the flag alone changes nothing (dt15 Grok Bot B2)
    const flagOnly = await check('GB-005').run(ctx([cfg({ egressTunnelEnabled: true })], makeFs({ env: { SAND_EGRESS_TUNNEL_ALLOW_PRIVATE: '1' } })));
    expect(flagOnly.severity).toBe('warning');
    const envTunnel = { SAND_EGRESS_TUNNEL_URL: 'https://tunnel.example', SAND_EGRESS_TUNNEL_ALLOW_PRIVATE: '1' };
    expect((await check('GB-005').run(ctx([], makeFs({ env: envTunnel })))).severity).toBe('critical');
    // Only exactly "1" turns it on (dt15 Grok Bot B3)
    const yes = await check('GB-005').run(ctx([], makeFs({ env: { ...envTunnel, SAND_EGRESS_TUNNEL_ALLOW_PRIVATE: 'yes' } })));
    expect(yes).toMatchObject({ passed: false, severity: 'warning' });
  });

  it('is info when team policy blocks local egress', async () => {
    const r = await check('GB-005').run(ctx([cfg({ egressTunnelEnabled: true, localEgressAllowed: false })]));
    expect(r).toMatchObject({ passed: false, severity: 'info' });
  });
});

describe('GB-006 credentials without keyring protection', () => {
  const CRED = `${ROOT}/local-exec-daemon-credential.json`;
  const SECRETS = `${UD}/sand-secrets.json`;
  const USER_SECRETS = `${UD}/user-secrets.json`;

  it('passes on sealed files and keyring (v11) values', async () => {
    const fs = makeFs({ files: {
      [CRED]: JSON.stringify({ sandSealedFile: 1, data: 'AAAA' }),
      [SECRETS]: JSON.stringify({ version: 1, 'cursor-machine-id': 'djExAAAA', 'local-exec-file-key': `scoped:v1:${'0'.repeat(64)}:djExBBBB` }),
    } });
    expect((await check('GB-006').run(ctx([], fs))).passed).toBe(true);
  });

  it('is critical for an unsealed credential and plaintext values, without quoting them', async () => {
    const fs = makeFs({ files: {
      [CRED]: JSON.stringify({ backendUrl: 'https://api2.cursor.sh', credential: 'SUPERSECRETTOKEN123' }),
      [SECRETS]: JSON.stringify({ version: 1, 'cursor-accounts': 'plaintext:v1:eyJzZWNyZXQiOjF9' }),
    } });
    const r = await check('GB-006').run(ctx([], fs));
    expect(r).toMatchObject({ passed: false, severity: 'critical' });
    expect(r.evidence).toHaveLength(2);
    expect(JSON.stringify(r.evidence)).not.toMatch(/SUPERSECRET|eyJzZWNyZXQ/);
  });

  it('warns on Linux basic_text (v10) values, including v2 user secrets', async () => {
    const fs = makeFs({ files: { [USER_SECRETS]: JSON.stringify({ version: 2, accounts: { a: { GITHUB_TOKEN: 'djEwAAAA' } } }) } });
    expect(await check('GB-006').run(ctx([], fs))).toMatchObject({ passed: false, severity: 'warning' });
    const mac = makeFs({ platform: 'darwin', files: { [`${HOME}/Library/Application Support/Grok Bot/user-secrets.json`]: JSON.stringify({ version: 1, secrets: { A: 'djEwAAAA' } }) } });
    expect((await check('GB-006').run(ctx([], mac))).passed).toBe(true);
  });

  it('finds raw tokens inside a cursor-accounts JSON document (dt15 Grok Bot B6)', async () => {
    const accounts = JSON.stringify({ active: 'a', accounts: { a: { 'cursor-access-token': 'eyFAKEACCESS', 'cursor-refresh-token': 'djExZW5j', 'cursor-account-profile': '{}' } } });
    const fs = makeFs({ files: { [SECRETS]: JSON.stringify({ version: 1, 'cursor-machine-id': 'djExAAAA', 'cursor-accounts': accounts }) } });
    const r = await check('GB-006').run(ctx([], fs));
    expect(r).toMatchObject({ passed: false, severity: 'critical' });
    expect(r.evidence![0].snippet).toContain('1 value(s)');
    expect(JSON.stringify(r.evidence)).not.toContain('eyFAKEACCESS');
  });

  it('notes stores it could not read (remote scans)', async () => {
    const r = await check('GB-006').run(ctx([], makeFs({ modes: { [SECRETS]: 0o600 } })));
    expect(r.passed).toBe(true);
    expect(r.message).toContain('not inspected');
  });
});

describe('GB-007 / GB-008 permissions', () => {
  it('GB-007 is critical for a group/world-accessible credential store', async () => {
    const fs = makeFs({ modes: { [`${UD}/sand-secrets.json`]: 0o644, [UD]: 0o755, [ROOT]: 0o755, ...OPEN_PARENTS } });
    const r = await check('GB-007').run(ctx([], fs));
    expect(r).toMatchObject({ passed: false, severity: 'critical', fixable: true });
  });

  it('GB-007 passes on 0600 files', async () => {
    const fs = makeFs({ modes: { [`${UD}/sand-secrets.json`]: 0o600, [`${ROOT}/local-exec-daemon-credential.json`]: 0o600 } });
    expect((await check('GB-007').run(ctx([], fs))).passed).toBe(true);
  });

  it('GB-008 warns on a readable client-persistence dir; files behind a 0700 parent are info', async () => {
    const live = makeFs({ modes: { [`${UD}/sand-client-persistence`]: 0o775, [UD]: 0o755, ...OPEN_PARENTS } });
    expect(await check('GB-008').run(ctx([], live))).toMatchObject({ passed: false, severity: 'warning' });
    // The box layout: 664 log and 775 dirs inside 0700 roots
    const box = makeFs({ modes: {
      [`${ROOT}/local-exec-daemon.log`]: 0o664, [ROOT]: 0o700, [UD]: 0o700,
      [`${UD}/sand-client-persistence`]: 0o775, [`${UD}/sand-statsig-bootstrap.json`]: 0o664, ...OPEN_PARENTS,
    } });
    const r = await check('GB-008').run(ctx([], box));
    // Every item mitigated → reported, but not offered to vaso fix
    expect(r).toMatchObject({ passed: false, severity: 'info', fixable: false });
  });
});

describe('GB-009 / GB-010 / GB-011', () => {
  it('GB-009 warns on macOS, is info elsewhere', async () => {
    const on = cfg({ messagesEnabled: true });
    expect(await check('GB-009').run(ctx([on], makeFs({ platform: 'darwin' })))).toMatchObject({ passed: false, severity: 'warning' });
    expect(await check('GB-009').run(ctx([on]))).toMatchObject({ passed: false, severity: 'info' });
    expect((await check('GB-009').run(ctx([cfg({ messagesEnabled: false })]))).passed).toBe(true);
  });

  it('GB-010 reports an open computer-use gate', async () => {
    const gate = `${ROOT}/local-computer-use-gate.json`;
    expect((await check('GB-010').run(ctx([], makeFs({ files: { [gate]: '{"isOn":false}' } })))).passed).toBe(true);
    expect(await check('GB-010').run(ctx([], makeFs({ files: { [gate]: '{"isOn":true}' } })))).toMatchObject({ passed: false, severity: 'info' });
  });

  it('GB-011 flags disabled updates (env, apt source) and the dogfood track', async () => {
    const apt = '/etc/apt/sources.list.d/grok-bot.sources';
    const enabled = '### THIS FILE IS AUTOMATICALLY CONFIGURED ###\nTypes: deb\nURIs: https://downloads.cursor.com/aptrepo\nSuites: grok-bot\n';
    expect((await check('GB-011').run(ctx([], makeFs({ files: { [apt]: enabled } })))).passed).toBe(true);
    const off = await check('GB-011').run(ctx([], makeFs({ files: { [apt]: `${enabled}Enabled: no\n` } })));
    expect(off).toMatchObject({ passed: false, severity: 'warning' });
    expect(await check('GB-011').run(ctx([], makeFs({ env: { SAND_DISABLE_UPDATES: '1' } })))).toMatchObject({ passed: false, severity: 'warning' });
    expect((await check('GB-011').run(ctx([], makeFs({ env: { SAND_DISABLE_UPDATES: 'true' } }))))).toMatchObject({ passed: true });
    expect(await check('GB-011').run(ctx([cfg({ updateTrackOverride: 'dogfood' })]))).toMatchObject({ passed: false, severity: 'info' });
  });
});

describe('GB-011 update tracks (dt16)', () => {
  it('passes on "nightly" — 0.71.2 coerces it to stable', async () => {
    expect((await check('GB-011').run(ctx([cfg({ updateTrackOverride: 'nightly' })]))).passed).toBe(true);
    expect((await check('GB-011').run(ctx([cfg({ updateTrackOverride: 'stable' })]))).passed).toBe(true);
  });

  it('marks "dogfood" ignored on a package-managed /opt install', async () => {
    const c = ctx([cfg({ updateTrackOverride: 'dogfood' })]);
    c.installation.appBundle = '/opt/Grok Bot';
    const r = await check('GB-011').run(c);
    expect(r).toMatchObject({ passed: false, severity: 'info' });
    expect(r.evidence![0]).toMatchObject({ mitigated: true });
    // An unknown track makes the app reject the whole file → defaults
    const bogus = cfg({ updateTrackOverride: 'beta', localToolPermission: 'always' });
    expect((await check('GB-001').run(ctx([bogus]))).passed).toBe(true);
  });
});

describe('GB-012 endpoint redirects (dt16)', () => {
  const run = (env: Record<string, string>, files: Record<string, string> = {}) =>
    check('GB-012').run(ctx([], makeFs({ env, files })));

  it('passes with no overrides and with vendor hosts', async () => {
    expect((await run({})).passed).toBe(true);
    expect((await run({ SAND_BACKEND_URL: 'https://api2.cursor.sh', SAND_CURSOR_WEBSITE_URL: 'https://cursor.com' })).passed).toBe(true);
    expect((await run({ CURSOR_API_BASE_URL: 'https://dev-staging.cursor.sh/' })).passed).toBe(true);
  });

  it('is critical for a redirected backend and never prints credentials or paths', async () => {
    const r = await run({ SAND_BACKEND_URL: 'https://user:hunter2@evil.example:8443/api?token=abc' });
    expect(r).toMatchObject({ passed: false, severity: 'critical' });
    expect(r.evidence![0].snippet).toBe('SAND_BACKEND_URL=https://evil.example:8443');
    expect(JSON.stringify(r)).not.toMatch(/hunter2|token=abc|\/api/);
    expect(await run({ CURSOR_API_BASE_URL: 'http://10.0.0.5:8000' })).toMatchObject({ passed: false, severity: 'critical' });
  });

  it('follows the app: SAND_BACKEND_URL wins over CURSOR_API_BASE_URL, even when unusable', async () => {
    expect((await run({ SAND_BACKEND_URL: 'https://api2.cursor.sh', CURSOR_API_BASE_URL: 'https://evil.example' })).passed).toBe(true);
    // "" makes the app fail on new URL(""), it does not fall through
    expect((await run({ SAND_BACKEND_URL: '', CURSOR_API_BASE_URL: 'https://evil.example' })).passed).toBe(true);
  });

  it('warns on a substitute cloud computer and sign-in page', async () => {
    const gw = await run({ SAND_HOST_GATEWAY_URL: 'https://box.evil.example', SAND_HOST_GATEWAY_TOKEN: 'secret-token' });
    expect(gw).toMatchObject({ passed: false, severity: 'warning' });
    expect(JSON.stringify(gw)).not.toContain('secret-token');
    expect(await run({ CURSOR_WEBSITE_URL: 'https://login.evil.example' })).toMatchObject({ passed: false, severity: 'warning' });
    expect((await run({ SAND_CURSOR_WEBSITE_URL: '', CURSOR_WEBSITE_URL: 'https://login.evil.example' })).passed).toBe(true);
  });

  it('is info for an explicit proxy the app accepts, and skips ones it ignores', async () => {
    expect(await run({ SAND_HTTPS_PROXY: 'http://proxy.corp:3128' })).toMatchObject({ passed: false, severity: 'info' });
    expect((await run({ SAND_HTTPS_PROXY: 'http://proxy.corp:3128/path' })).passed).toBe(true);
    expect((await run({ SAND_HTTPS_PROXY: 'socks5://proxy.corp:1080' })).passed).toBe(true);
    expect((await run({ SAND_HTTPS_PROXY: 'http://proxy.corp:3128', SAND_SYSTEM_PROXY: '0' })).passed).toBe(true);
    expect((await run({ SAND_HTTPS_PROXY: 'http://proxy.corp:3128', NODE_USE_ENV_PROXY: '1' })).passed).toBe(true);
  });

  it('reports a recorded host-gateway binding (info), and ignores env for other users', async () => {
    const r = await run({}, { [`${UD}/.env-descriptor-account-bindings.json`]: '{"version":1,"bindings":{}}' });
    expect(r).toMatchObject({ passed: false, severity: 'info' });
    const other = ctx([], makeFs({ env: { SAND_BACKEND_URL: 'https://evil.example' } }));
    other.installation.installDir = '/home/other/.grokbot';
    expect((await check('GB-012').run(other)).passed).toBe(true);
  });
});

describe('GB-013 passkey proxy (dt16)', () => {
  it('is info by default on macOS and Windows, passes when off or on Linux', async () => {
    expect(await check('GB-013').run(ctx([], makeFs({ platform: 'darwin' })))).toMatchObject({ passed: false, severity: 'info' });
    expect(await check('GB-013').run(ctx([cfg({ webauthnProxyEnabled: true })], makeFs({ platform: 'win32' })))).toMatchObject({ passed: false, severity: 'info' });
    expect((await check('GB-013').run(ctx([cfg({ webauthnProxyEnabled: false })], makeFs({ platform: 'darwin' })))).passed).toBe(true);
    expect((await check('GB-013').run(ctx([]))).passed).toBe(true);
    // A file the app rejects means the default (on)
    const rejected = cfg({ webauthnProxyEnabled: false, version: 2 });
    expect((await check('GB-013').run(ctx([rejected], makeFs({ platform: 'darwin' })))).passed).toBe(false);
  });
});
