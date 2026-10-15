import { describe, it, expect, afterEach } from 'vitest';
import { mkdtemp, mkdir, writeFile, rm, chmod, stat } from 'node:fs/promises';
import { join } from 'node:path';
import type { AgentInstallation, ParsedConfig, ScanContext } from '../../core/types.js';
import type { FSProvider } from '../../core/fs-provider.js';
import { LocalFSProvider } from '../../core/local-fs-provider.js';
import { SnapshotFSProvider } from '../../core/snapshot-fs-provider.js';
import { openclawAdapter } from '../../adapters/openclaw.js';
import { findNanoclawCheckouts } from '../../adapters/nanoclaw.js';
import { applyEnvOverrides } from '../../adapters/env-overrides.js';
import { extractPosture } from '../openclaw/posture.js';
import { cfg001 } from './cfg-001-gateway-binding.js';
import { cfg004 } from './cfg-004-tls-config.js';
import { cfg009 } from './cfg-009-default-credentials.js';
import { cfg012 } from './cfg-012-auth-bypass.js';
import { net001 } from '../network/net-001-gateway-exposure.js';
import { at005 } from '../atomic-agent/at-005-credential-file-perms.js';
import { hm003 } from '../hermes/hm-003-credential-file-perms.js';
import { zc014 } from '../zeroclaw/zc-014-no-os-sandbox.js';

const json = (filePath: string, data: Record<string, unknown>): ParsedConfig =>
  ({ filePath, format: 'json', raw: JSON.stringify(data), data });

function ctx(
  agent: AgentInstallation['agent'],
  configs: ParsedConfig[],
  extra: Partial<AgentInstallation> = {},
  fs: FSProvider = new LocalFSProvider(),
): ScanContext {
  const merged = Object.assign({}, ...configs.map(c => c.data)) as Record<string, unknown>;
  const installation: AgentInstallation = {
    agent,
    installDir: '/h/.openclaw',
    configFiles: configs,
    gateway: agent === 'openclaw' ? openclawAdapter.getGatewayInfo(merged) : undefined,
    ...extra,
  };
  return { installation, configs, platform: 'linux', fs };
}

describe('OpenClaw gateway (2026.9.4 runtime semantics)', () => {
  it('an unset gateway.bind is loopback, not an exposed listener without TLS', async () => {
    expect(openclawAdapter.getGatewayInfo({ gateway: { port: 18789 } })?.host).toBe('127.0.0.1');
    expect((await cfg004.run(ctx('openclaw', [json('/h/.openclaw/openclaw.json', { gateway: { port: 18789 } })]))).passed).toBe(true);
  });

  it('remote mode runs no local listener; a plaintext ws:// remote URL is the TLS finding', async () => {
    const remote = (url: string, extra: Record<string, unknown> = {}) =>
      json('/h/.openclaw/openclaw.json', { gateway: { mode: 'remote', bind: 'lan', remote: { url, ...extra } } });
    expect(openclawAdapter.getGatewayInfo(remote('wss://gw.example.com').data)).toBeUndefined();
    expect((await cfg001.run(ctx('openclaw', [remote('wss://gw.example.com')]))).passed).toBe(true);
    expect((await cfg004.run(ctx('openclaw', [remote('wss://gw.example.com')]))).passed).toBe(true);
    expect((await cfg004.run(ctx('openclaw', [remote('ws://gw.example.com:18789')]))).passed).toBe(false);
    expect((await cfg004.run(ctx('openclaw', [remote('ws://gw.example.com', { transport: 'ssh' })]))).passed).toBe(true);
    expect((await cfg004.run(ctx('openclaw', [remote('ws://127.0.0.1:18789')]))).passed).toBe(true);
  });

  it('non-string gateway values do not crash the checks', async () => {
    const odd = json('/h/.openclaw/openclaw.json', { gateway: { host: 42, port: '18789', auth: { mode: ['none'] }, tls: 'yes' } });
    const info = openclawAdapter.getGatewayInfo(odd.data);
    expect(info?.host).toBeUndefined();
    expect(info?.authMode).toBeUndefined();
    for (const check of [cfg001, cfg004, net001]) {
      const r = await check.run(ctx('openclaw', [odd]));
      expect(r.errored).toBeFalsy();
    }
    expect(extractPosture({ gateway: { auth: { mode: 7 }, host: {} } })).toMatchObject({ authMode: undefined, gatewayHost: undefined });
  });
});

describe('NET-001', () => {
  it('flags [::] and * like 0.0.0.0', async () => {
    for (const host of ['[::]', '::', '*', '0.0.0.0']) {
      const c = ctx('hermes', [], { gateway: { host } });
      expect((await net001.run(c)).passed, host).toBe(false);
    }
    expect((await net001.run(ctx('hermes', [], { gateway: { host: '127.0.0.1' } }))).passed).toBe(true);
  });

  it('reports an OpenClaw Tailscale Funnel as internet exposure (warning), not "not publicly exposed"', async () => {
    const funnel = json('/h/.openclaw/openclaw.json', { gateway: { bind: 'loopback', tailscale: { mode: 'funnel' }, auth: { mode: 'password' } } });
    const r = await net001.run(ctx('openclaw', [funnel]));
    expect(r.passed).toBe(false);
    expect(r.severity).toBe('warning');
    const serve = json('/h/.openclaw/openclaw.json', { gateway: { bind: 'loopback', tailscale: { mode: 'serve' } } });
    expect((await net001.run(ctx('openclaw', [serve]))).passed).toBe(true);
  });
});

describe('CFG-009 documentation placeholders', () => {
  const run = (token: string) => cfg009.run(ctx('openclaw', [json('/h/.openclaw/openclaw.json', { gateway: { auth: { mode: 'token', token } } })]));
  it('flags tokens copied from docs', async () => {
    for (const t of ['replace-with-long-random-token', 'abcd1234efgh5678ijkl', 'your_token_here', '<token>', 'xxxxxxxx']) {
      expect((await run(t)).passed, t).toBe(false);
    }
  });
  it('leaves random tokens and env references alone', async () => {
    for (const t of ['9f8e7d6c5b4a39281706f5e4d3c2b1a0', 'Zx8f3kq9Lm2Rt7Vb4Nc6Hd1Jw5Ys0Pa', '${OPENCLAW_GATEWAY_TOKEN}']) {
      expect((await run(t)).passed, t).toBe(true);
    }
  });
});

describe('CFG-009 severity follows how far the gateway can be reached', () => {
  const oc = (gateway: Record<string, unknown>) =>
    cfg009.run(ctx('openclaw', [json('/h/.openclaw/openclaw.json', { gateway: { ...gateway, auth: { mode: 'token', token: 'replace-with-long-random-token' } } })]));
  it('warning on a loopback-only gateway, critical once it is reachable', async () => {
    expect((await oc({})).severity).toBe('warning');
    expect((await oc({ bind: 'loopback' })).severity).toBe('warning');
    expect((await oc({ bind: 'lan' })).severity).toBe('critical');
    expect((await oc({ bind: 'loopback', tailscale: { mode: 'funnel' } })).severity).toBe('critical');
  });
  it('stays critical when the detected gateway host is not loopback (older `gateway.host` configs)', async () => {
    const r = await cfg009.run(ctx('openclaw',
      [json('/h/.openclaw/openclaw.json', { gateway: { host: '0.0.0.0', auth: { mode: 'token', token: 'changeme' } } })],
      { gateway: { host: '0.0.0.0', port: 8080 } }));
    expect(r.severity).toBe('critical');
  });
  it('uses the detected gateway host for other agents; unknown exposure stays critical', async () => {
    const cfg = json('/h/.x/config.json', { auth: { token: 'changeme' } });
    expect((await cfg009.run(ctx('hermes', [cfg], { gateway: { host: '127.0.0.1', port: 8642 } }))).severity).toBe('warning');
    expect((await cfg009.run(ctx('hermes', [cfg], { gateway: { host: '0.0.0.0', port: 8642 } }))).severity).toBe('critical');
    expect((await cfg009.run(ctx('hermes', [cfg]))).severity).toBe('critical');
  });
});

describe('CFG-001 with a host set only by an env override', () => {
  it('reports the variable and offers no file fix', async () => {
    const fakeFs = { getEnv: (n: string) => (n === 'ZEROCLAW_GATEWAY_HOST' ? '0.0.0.0' : undefined) } as unknown as FSProvider;
    const data = applyEnvOverrides({ gateway: { port: 42617 } }, [{ env: 'ZEROCLAW_GATEWAY_HOST', path: ['gateway', 'host'], type: 'string' }], fakeFs);
    const r = await cfg001.run(ctx('zeroclaw', [{ filePath: '/h/.zeroclaw/config.toml', format: 'toml', raw: '[gateway]\nport = 42617\n', data }]));
    expect(r.passed).toBe(false);
    expect(r.fixable).toBe(false);
    expect(r.evidence?.[0].detail).toContain('ZEROCLAW_GATEWAY_HOST');
  });
});

describe('CFG-012 and OpenClaw sub-agents', () => {
  it('leaves a gateway section in a sub-agent file to OC-001; the main config still counts', async () => {
    const main = json('/h/.openclaw/openclaw.json', { gateway: { auth: { mode: 'token' } } });
    const sub = json('/h/.openclaw/agents/evil/agent.json', { gateway: { auth: { mode: 'none', bypass: true } } });
    const subCtx = ctx('openclaw', [main, sub], { installDir: '/h/.openclaw/agents/evil', agentName: 'evil' });
    expect((await cfg012.run(subCtx)).passed).toBe(true);
    const weakMain = json('/h/.openclaw/openclaw.json', { gateway: { auth: { mode: 'none' } } });
    expect((await cfg012.run(ctx('openclaw', [weakMain, sub], { installDir: '/h/.openclaw/agents/evil', agentName: 'evil' }))).passed).toBe(false);
  });
});

describe('NanoClaw checkouts on a case-insensitive file system', () => {
  it('~/projects and ~/Projects are one checkout in a macOS snapshot', async () => {
    const pkg = { content: '{"name":"nanoclaw","version":"2.4.0"}', mode: 0o644, exists: true };
    const snapshot = (platform: 'darwin' | 'linux') => new SnapshotFSProvider({
      version: 1, hostname: 'h', platform, homedir: '/h', timestamp: 't',
      privilege: { uid: 1, username: 'u', isRoot: false, sudoAvailable: false, escalated: false, scannedUsers: ['u'], skippedPaths: [] },
      files: { '/h/projects/nanoclaw/package.json': pkg, '/h/Projects/nanoclaw/package.json': pkg },
      directories: {}, commandOutputs: {}, env: {},
    });
    expect(await findNanoclawCheckouts('/h', snapshot('darwin'))).toHaveLength(1);
    expect(await findNanoclawCheckouts('/h', snapshot('linux'))).toHaveLength(2);
  });
});

describe.skipIf(process.platform === 'win32')('AT-005 / HM-003 fixes', () => {
  let dir = '';
  afterEach(async () => { if (dir) await rm(dir, { recursive: true, force: true }); });

  it('AT-005 restricts .env and atomic-mail/session.json', async () => {
    dir = await mkdtemp('/tmp/vaso-at005-');
    await chmod(dir, 0o755); // reachable by others, or the finding is mitigated
    await mkdir(join(dir, 'atomic-mail'), { mode: 0o755 });
    for (const f of ['.env', 'atomic-mail/session.json']) {
      await writeFile(join(dir, f), 'x');
      await chmod(join(dir, f), 0o644);
    }
    const c = ctx('atomic-agent', [], { installDir: dir });
    const r = await at005.run(c);
    expect(r.passed).toBe(false);
    expect(r.fixable).toBe(true);
    expect((await at005.fix!(c)).applied).toBe(true);
    for (const f of ['.env', 'atomic-mail/session.json']) expect((await stat(join(dir, f))).mode & 0o077).toBe(0);
    expect((await at005.run(c)).passed).toBe(true);
  });

  it('HM-003 restricts auth.json and mcp-tokens/*.json', async () => {
    dir = await mkdtemp('/tmp/vaso-hm003-');
    await chmod(dir, 0o755);
    await mkdir(join(dir, 'mcp-tokens'), { mode: 0o755 });
    for (const f of ['auth.json', 'mcp-tokens/srv.json']) {
      await writeFile(join(dir, f), '{}');
      await chmod(join(dir, f), 0o644);
    }
    const c = ctx('hermes', [], { installDir: dir });
    expect((await hm003.run(c)).fixable).toBe(true);
    expect((await hm003.fix!(c)).applied).toBe(true);
    expect((await hm003.run(c)).passed).toBe(true);
  });
});

describe('ZC-014', () => {
  it('does not claim isolation for backend "auto"', async () => {
    const c = ctx('zeroclaw', [{ filePath: '/h/.zeroclaw/config.toml', format: 'toml', raw: '', data: {} }]);
    const r = await zc014.run(c);
    expect(r.passed).toBe(true);
    expect(r.message).toContain('zeroclaw security status');
  });
});
