import { describe, it, expect } from 'vitest';
import type { ParsedConfig, ScanContext } from '../../core/types.js';
import type { FSProvider } from '../../core/fs-provider.js';
import { oc008, openclawGatewayExposed } from './oc-008-dangerous-gateway-overrides.js';
import { cfg015 } from '../config/cfg-015-mdns-broadcast.js';

const FILE = '/home/u/.openclaw/openclaw.json';
// The hardened baseline the OpenClaw security docs recommend
const BASE = { gateway: { mode: 'local', bind: 'loopback', auth: { mode: 'token', token: 'Zx8f3kq9Lm2Rt7Vb4Nc6Hd1Jw5Ys0Pa' } } };

function ctx(data: Record<string, unknown>, agentName?: string): ScanContext {
  const config: ParsedConfig = { raw: JSON.stringify(data), format: 'json', filePath: FILE, data };
  return {
    installation: { agent: 'openclaw', installDir: '/home/u/.openclaw', configFiles: [config], ...(agentName ? { agentName } : {}) },
    configs: [config],
    platform: 'linux',
    fs: {} as FSProvider,
  };
}

const merge = (extra: Record<string, unknown>) => {
  const out = structuredClone(BASE) as Record<string, any>;
  for (const [k, v] of Object.entries(extra)) {
    out[k] = typeof v === 'object' && v && !Array.isArray(v) ? { ...(out[k] ?? {}), ...v } : v;
  }
  return out;
};

describe('OC-008 dangerous gateway overrides', () => {
  it('passes the hardened baseline', async () => {
    expect((await oc008.run(ctx(BASE))).passed).toBe(true);
  });

  it('elevated allowFrom "*" is critical; disabled elevated or a narrow list passes', async () => {
    const wild = await oc008.run(ctx(merge({ tools: { elevated: { enabled: true, allowFrom: { whatsapp: ['*'] } } } })));
    expect(wild).toMatchObject({ passed: false, severity: 'critical' });
    expect((await oc008.run(ctx(merge({ tools: { elevated: { enabled: false, allowFrom: { whatsapp: ['*'] } } } })))).passed).toBe(true);
    expect((await oc008.run(ctx(merge({ tools: { elevated: { allowFrom: { whatsapp: ['+15551234567'] } } } })))).passed).toBe(true);
  });

  it('gateway.tools.allow re-enabling exec is critical when reachable, warning on loopback; harmless tools pass', async () => {
    expect(await oc008.run(ctx(merge({ gateway: { ...BASE.gateway, tools: { allow: ['exec'] } } }))))
      .toMatchObject({ passed: false, severity: 'warning' });
    expect(await oc008.run(ctx(merge({ gateway: { ...BASE.gateway, bind: 'lan', tools: { allow: ['gateway'] } } }))))
      .toMatchObject({ passed: false, severity: 'critical' });
    expect((await oc008.run(ctx(merge({ gateway: { ...BASE.gateway, tools: { allow: ['web_search'] } } })))).passed).toBe(true);
  });

  it('X-Real-IP fallback is critical on a reachable gateway, info on loopback', async () => {
    expect(await oc008.run(ctx(merge({ gateway: { ...BASE.gateway, allowRealIpFallback: true } }))))
      .toMatchObject({ passed: false, severity: 'info' });
    expect(await oc008.run(ctx(merge({ gateway: { ...BASE.gateway, tailscale: { mode: 'serve' }, allowRealIpFallback: true } }))))
      .toMatchObject({ passed: false, severity: 'critical' });
  });

  it('dangerous node commands: info on loopback, warning when reachable; deny wins', async () => {
    const nodes = (extra: object) => merge({ gateway: { ...BASE.gateway, ...extra, nodes: { commands: { allow: ['screen.record', 'camera.snap', 'sms.send'] } } } });
    expect(await oc008.run(ctx(nodes({})))).toMatchObject({ passed: false, severity: 'info' });
    expect(await oc008.run(ctx(nodes({ bind: 'lan' })))).toMatchObject({ passed: false, severity: 'warning' });
    const denied = merge({ gateway: { ...BASE.gateway, nodes: { commands: { allow: ['screen.record'], deny: ['screen.record'] } } } });
    expect((await oc008.run(ctx(denied))).passed).toBe(true);
  });

  it('hook findings only while hooks are enabled', async () => {
    const hooks = (enabled: boolean) => merge({ hooks: { enabled, token: 't'.repeat(32), path: '/', allowRequestSessionKey: true } });
    const on = await oc008.run(ctx(hooks(true)));
    expect(on).toMatchObject({ passed: false, severity: 'warning' });
    expect(on.evidence?.map(e => e.detail).join('\n')).toMatch(/hooks\.path = "\/"[\s\S]*|allowRequestSessionKey/);
    expect((await oc008.run(ctx(hooks(false)))).passed).toBe(true);
  });

  it('browser private-network SSRF override is a warning', async () => {
    expect(await oc008.run(ctx(merge({ browser: { ssrfPolicy: { dangerouslyAllowPrivateNetwork: true } } }))))
      .toMatchObject({ passed: false, severity: 'warning' });
  });

  it('skips remote mode and sub-agent installations', async () => {
    const wild = { tools: { elevated: { allowFrom: { telegram: ['*'] } } } };
    expect((await oc008.run(ctx(merge({ ...wild, gateway: { mode: 'remote', remote: { url: 'wss://gw.example.com' } } })))).passed).toBe(true);
    expect((await oc008.run(ctx(merge(wild), 'helper'))).passed).toBe(true);
  });

  it('exposure follows OpenClaw: unset bind is loopback; custom loopback host stays local', () => {
    expect(openclawGatewayExposed({ gateway: {} })).toBe(false);
    expect(openclawGatewayExposed({ gateway: { bind: 'custom', customBindHost: '127.0.0.1' } })).toBe(false);
    expect(openclawGatewayExposed({ gateway: { bind: 'tailnet' } })).toBe(true);
    expect(openclawGatewayExposed({ gateway: { tailscale: { mode: 'funnel' } } })).toBe(true);
  });
});

describe('CFG-015 OpenClaw mDNS full mode', () => {
  it('is info on a loopback gateway and a warning on a reachable one', async () => {
    const full = { discovery: { mdns: { mode: 'full' } } };
    expect(await cfg015.run(ctx(merge(full)))).toMatchObject({ passed: false, severity: 'info' });
    expect(await cfg015.run(ctx(merge({ ...full, gateway: { ...BASE.gateway, bind: 'lan' } })))).toMatchObject({ passed: false, severity: 'warning' });
    expect((await cfg015.run(ctx(merge({ discovery: { mdns: { mode: 'minimal' } } })))).passed).toBe(true);
  });
});
