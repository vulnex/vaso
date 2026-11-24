import { describe, it, expect } from 'vitest';
import type { ParsedConfig, ScanContext } from '../../core/types.js';
import { LocalFSProvider } from '../../core/local-fs-provider.js';
import { nanobotAdapter } from '../../adapters/nanobot.js';
import { cfg001 } from './cfg-001-gateway-binding.js';
import { cfg004 } from './cfg-004-tls-config.js';

// Nanobot's websocket channel (dt20 g5): runtime.py serves wss:// when
// sslCertfile and sslKeyfile are both set, and a unix socket instead of TCP
// when unixSocketPath is set.
function ctx(ws: Record<string, unknown>): ScanContext {
  const data = { channels: { websocket: ws } };
  const config: ParsedConfig = { filePath: '/h/.nanobot/config.json', format: 'json', raw: JSON.stringify(data), data };
  return {
    installation: { agent: 'nanobot', installDir: '/h/.nanobot', configFiles: [config], gateway: nanobotAdapter.getGatewayInfo(data) },
    configs: [config],
    platform: 'linux',
    fs: new LocalFSProvider(),
  };
}

describe('Nanobot websocket channel', () => {
  it('CFG-004 passes a wildcard bind serving wss:// (camelCase and snake_case)', async () => {
    for (const ws of [
      { host: '0.0.0.0', sslCertfile: '/etc/c.pem', sslKeyfile: '/etc/k.pem' },
      { host: '0.0.0.0', ssl_certfile: '/etc/c.pem', ssl_keyfile: '/etc/k.pem' },
    ]) {
      expect((await cfg004.run(ctx(ws))).passed).toBe(true);
    }
  });

  it('CFG-004 still flags ws:// and a certificate without its key', async () => {
    // nanobot refuses an unauthenticated websocket on 0.0.0.0, so these carry a token
    expect((await cfg004.run(ctx({ host: '0.0.0.0', token: 't' }))).passed).toBe(false);
    expect((await cfg004.run(ctx({ host: '0.0.0.0', token: 't', sslCertfile: '/etc/c.pem' }))).passed).toBe(false);
  });

  it('CFG-001 ignores the host of a channel served on a unix socket', async () => {
    const r = await cfg001.run(ctx({ unixSocketPath: '/run/nanobot.sock', host: '0.0.0.0' }));
    expect(r.passed).toBe(true);
    // An empty unixSocketPath keeps the TCP listener (a token keeps the
    // config loadable — see below)
    expect((await cfg001.run(ctx({ unix_socket_path: '', host: '0.0.0.0', token: 't' }))).passed).toBe(false);
  });

  // nanobot-ai 0.4.1 channels/websocket/runtime.py WebSocketConfig
  // wildcard_host_requires_auth: host exactly "0.0.0.0" or "::" with no
  // token, token_issue_secret or trusted_proxy_auth raises — config.json is
  // rejected and nothing listens (NB-008 reports it)
  it('CFG-001 skips a wildcard websocket nanobot refuses to load, and a host that never binds', async () => {
    for (const ws of [
      { unix_socket_path: '', host: '0.0.0.0' },
      { enabled: true, host: '::' },
      { host: '0.0.0.0', token: '  ' },
      { host: '[::]' },
      { host: '[::]', token: 't' },
    ]) {
      expect((await cfg001.run(ctx(ws))).passed, JSON.stringify(ws)).toBe(true);
    }
    // loadable wildcard binds are still reported
    for (const ws of [{ host: '::', token: 't' }, { host: '0.0.0.0', tokenIssueSecret: 's' }, { host: '0.0.0.0', trusted_proxy_auth: {} }, { host: '' }]) {
      expect((await cfg001.run(ctx(ws))).passed, JSON.stringify(ws)).toBe(false);
    }
  });

  it('CFG-001 names the IPv6 wildcard it found', async () => {
    const r = await cfg001.run(ctx({ host: '::', token: 't' }));
    expect(r.passed).toBe(false);
    expect(r.message).toBe('Gateway is bound to :: — accessible from all network interfaces');
    expect((await cfg001.run(ctx({ host: '0.0.0.0', token: 't' }))).message)
      .toBe('Gateway is bound to 0.0.0.0 — accessible from all network interfaces');
  });
});
