import { describe, it, expect } from 'vitest';
import type { ParsedConfig, ScanContext } from '../core/types.js';
import { LocalFSProvider } from './local-fs-provider.js';
import { hostPort, isLoopbackAddress, isWildcardAddress, wildcardFamilyLabel } from './listen-address.js';
import { nanobotAdapter } from '../adapters/nanobot.js';
import { picoclawAdapter } from '../adapters/picoclaw.js';
import { cfg001 } from '../checks/config/cfg-001-gateway-binding.js';
import { net001 } from '../checks/network/net-001-gateway-exposure.js';
import { isWildcardHost } from '../checks/ironclaw/layout.js';
import { nanobotChecks } from '../checks/nanobot/index.js';

// dt21 g5-F3: every spelling of "all interfaces" is one.

describe('isWildcardAddress', () => {
  it('accepts every all-zero IPv4 / IPv6 spelling, brackets, zone and whitespace', () => {
    for (const h of ['0.0.0.0', '0', '000.0.0.0', '0.0', '::', '::0', '[::]', '[::0]', '0:0:0:0:0:0:0:0', '0000:0000::',
      '::0000', '0::0', ' 0.0.0.0 ', '::%eth0', '*']) {
      expect(isWildcardAddress(h), h).toBe(true);
    }
  });

  it('rejects specific hosts and malformed zero runs', () => {
    for (const h of ['127.0.0.1', '10.0.0.5', 'localhost', '::1', '0.0.0.1', '0:0:0:0:0:0:0:0:0', ':::', '00000::', '0.0.0.0.0', 'host0']) {
      expect(isWildcardAddress(h), h).toBe(false);
    }
  });

  it('counts an empty host only when the listener binds everything for it, and only exactly empty (dt21 g5-R3)', () => {
    expect(isWildcardAddress('')).toBe(false);
    expect(isWildcardAddress('', { emptyIsWildcard: true })).toBe(true);
    // asyncio fails to resolve a whitespace-only host: nothing listens
    expect(isWildcardAddress('  ', { emptyIsWildcard: true })).toBe(false);
  });

  it('accepts the spellings Python and Node bind on every interface (dt21 g8-R9)', () => {
    // verified: asyncio.start_server / net.listen on macOS bind 0.0.0.0 for 0x0, :: for ::0.0.0.0;
    // Node listens on :: for ::ffff:0.0.0.0 (Linux binds every IPv4 address)
    for (const h of ['0x0', '0x0.0', '0X00', '::0.0.0.0', '0:0:0:0:0:0:0.0.0.0', '::ffff:0.0.0.0', '::ffff:0:0']) {
      expect(isWildcardAddress(h), h).toBe(true);
    }
    for (const h of ['::0.0.0.1', '::ffff:127.0.0.1', '::ffff:0.0.0.256', '0x1', '1::']) {
      expect(isWildcardAddress(h), h).toBe(false);
    }
  });

  it('reads loopback in every spelling the socket layer binds as loopback (dt21 g5-R2-6)', () => {
    // verified: asyncio / net.listen on macOS bind 127.1, 0x7f.1, 0x7f000001, 2130706433 to 127.0.0.1;
    // Node binds ::ffff:127.0.0.1 as loopback; 0177.0.0.1 is octal 127 on Linux (macOS can't bind it)
    for (const h of ['127.0.0.1', '127.1', '0x7f.1', '0x7f000001', '2130706433', '127.000.000.001', '0177.0.0.1', '127.0.0.2',
      '::1', '[::1]', '0:0:0:0:0:0:0:1', '::ffff:127.0.0.1', '::ffff:7f00:1', 'localhost', 'app.localhost']) {
      expect(isLoopbackAddress(h), h).toBe(true);
    }
    for (const h of ['128.0.0.1', '10.0.0.5', '0.0.0.0', '::', '::2', '08.0.0.1', 'example.com', '1.2.3.4.5']) {
      expect(isLoopbackAddress(h), h).toBe(false);
    }
  });

  it('brackets an IPv6 host in host:port (dt21 g5-R4)', () => {
    expect(hostPort('::0', 8765)).toBe('[::0]:8765');
    expect(hostPort('[::]', 1)).toBe('[::]:1');
    expect(hostPort('0.0.0.0', 2)).toBe('0.0.0.0:2');
  });

  it('labels the address family for messages', () => {
    expect(wildcardFamilyLabel('::0')).toBe('::');
    expect(wildcardFamilyLabel('0')).toBe('0.0.0.0');
  });

  it('is what IronClaw\'s isWildcardHost uses (empty = unset)', () => {
    expect(isWildcardHost('::0')).toBe(true);
    expect(isWildcardHost('0')).toBe(true);
    expect(isWildcardHost('')).toBe(false);
  });
});

function ctx(agent: 'nanobot' | 'zeroclaw' | 'picoclaw', data: Record<string, unknown>, gateway?: ScanContext['installation']['gateway'], extra: ParsedConfig[] = []): ScanContext {
  const config: ParsedConfig = { filePath: `/h/.${agent}/config.json`, format: 'json', raw: JSON.stringify(data, null, 2), data };
  return {
    installation: { agent, installDir: `/h/.${agent}`, configFiles: [config, ...extra], gateway },
    configs: [config, ...extra],
    platform: 'linux',
    fs: new LocalFSProvider(),
  };
}

describe('Nanobot websocket host spellings (CFG-001 / NET-001 / NB-008)', () => {
  const nb = (host: string) => {
    const data = { channels: { websocket: { host, websocketRequiresToken: false } } };
    return ctx('nanobot', data, nanobotAdapter.getGatewayInfo(data));
  };

  for (const host of ['', '0', '::0', '0:0:0:0:0:0:0:0', '0.0.0.0 ', '0000:0000::']) {
    it(`reports host ${JSON.stringify(host)} as all interfaces`, async () => {
      expect((await cfg001.run(nb(host))).passed).toBe(false);
      expect((await net001.run(nb(host))).passed).toBe(false);
      const nb008 = await nanobotChecks.find(c => c.id === 'NB-008')!.run(nb(host));
      expect(nb008.severity).toBe('critical');
    });
  }

  it('NET-001 brackets an IPv6 host', async () => {
    expect((await net001.run(nb('::0'))).message).toBe('Gateway bound to [::0]:8765 — exposed to all network interfaces');
  });

  it('treats a whitespace-only host as no listener (asyncio cannot resolve it) (dt21 g5-R3)', async () => {
    const data = { channels: { websocket: { host: ' ', websocketRequiresToken: false } } };
    expect(nanobotAdapter.getGatewayInfo(data)).toBeUndefined();
    expect((await cfg001.run(nb(' '))).passed).toBe(true);
    expect((await net001.run(nb(' '))).passed).toBe(true);
    expect((await nanobotChecks.find(c => c.id === 'NB-008')!.run(nb(' '))).severity).not.toBe('critical');
  });

  it('keeps an absent host on the 127.0.0.1 default, and localhost / a LAN address as they are', async () => {
    const data = { channels: { websocket: { websocketRequiresToken: false } } };
    expect(nanobotAdapter.getGatewayInfo(data)?.host).toBe('127.0.0.1');
    expect((await cfg001.run(nb('localhost'))).passed).toBe(true);
    expect((await net001.run(nb('localhost'))).passed).toBe(true);
    expect((await cfg001.run(nb('10.0.0.5'))).passed).toBe(true);
  });

  it('names the configured spelling in CFG-001 and NET-001 alike (dt21 g4-R2-3)', async () => {
    expect((await cfg001.run(nb('::0'))).message).toBe('Gateway is bound to ::0 — accessible from all network interfaces');
    expect((await net001.run(nb('::0'))).message).toBe('Gateway bound to [::0]:8765 — exposed to all network interfaces');
  });

  it('reads 127.1 as loopback for NB-008 (dt21 g5-R2-6)', async () => {
    expect((await nanobotChecks.find(c => c.id === 'NB-008')!.run(nb('127.1'))).severity).not.toBe('critical');
  });
});

describe('generic gateway hosts', () => {
  it('flags ZeroClaw host "::0" in CFG-001 and NET-001', async () => {
    const c = ctx('zeroclaw', { gateway: { host: '::0', port: 42617 } }, { host: '::0', port: 42617 });
    expect((await cfg001.run(c)).passed).toBe(false);
    expect((await net001.run(c)).passed).toBe(false);
  });

  it('does not read a bare "0" under a key that isn\'t an address as a bind', async () => {
    const c = ctx('zeroclaw', { ssh: { hostKeyChecking: '0' }, gateway: { host: '127.0.0.1' } });
    expect((await cfg001.run(c)).passed).toBe(true);
  });

  it('normalises PicoClaw comma lists', () => {
    // the wildcard as configured, IPv4 first (dt21 g4-R2-3)
    expect(picoclawAdapter.getGatewayInfo({ gateway: { host: '127.0.0.1,::0' } })?.host).toBe('::0');
    expect(picoclawAdapter.getGatewayInfo({ gateway: { host: '::0,0' } })?.host).toBe('0');
    expect(picoclawAdapter.getGatewayInfo({ gateway: { host: '*' } })?.host).toBe('0.0.0.0');
  });
});

describe('PicoClaw public launcher (dt21 g4-F4)', () => {
  const launcherData = { public: true };
  const launcher: ParsedConfig = {
    filePath: '/h/.picoclaw/launcher-config.json', format: 'json',
    raw: '{\n  "port": 18800,\n  "public": true\n}', data: launcherData,
  };

  it('names launcher-config.json and offers no config.json fix', async () => {
    const data = { gateway: { host: '0.0.0.0', port: 18790 } };
    const r = await cfg001.run(ctx('picoclaw', data, { host: '0.0.0.0', port: 18790 }, [launcher]));
    expect(r.passed).toBe(false);
    expect(r.fixable).toBe(false);
    expect(r.evidence!.some(e => e.file === launcher.filePath && e.line === 3 && /public: true/.test(e.detail ?? ''))).toBe(true);
  });

  it('reports the launcher even when gateway.host is loopback', async () => {
    const r = await cfg001.run(ctx('picoclaw', { gateway: { host: '127.0.0.1' } }, { host: '0.0.0.0', port: 18790 }, [launcher]));
    expect(r.passed).toBe(false);
    expect(r.evidence!.map(e => e.file)).toEqual([launcher.filePath]);
    expect(r.fixable).toBe(false);
  });

  it('keeps the gateway.host fix without a public launcher', async () => {
    const r = await cfg001.run(ctx('picoclaw', { gateway: { host: '0.0.0.0' } }, { host: '0.0.0.0', port: 18790 }));
    expect(r.fixable).toBe(true);
  });
});
