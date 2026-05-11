import { describe, it, expect } from 'vitest';
import type { ScanContext, AgentInstallation, ParsedConfig, GatewayInfo } from '../../core/types.js';
import { LocalFSProvider } from '../../core/local-fs-provider.js';
import { net001 } from './net-001-gateway-exposure.js';
import { net002 } from './net-002-websocket-origin.js';
import { net003 } from './net-003-reverse-proxy.js';
import { net004 } from './net-004-port-scan.js';
import { net005 } from './net-005-active-connections.js';

function makeContext(gateway?: GatewayInfo, configs: ParsedConfig[] = []): ScanContext {
  const installation: AgentInstallation = {
    agent: 'openclaw',
    installDir: '/tmp/test-openclaw',
    configFiles: configs,
    gateway,
  };
  return { installation, configs, platform: process.platform as NodeJS.Platform, fs: new LocalFSProvider() };
}

function makeConfig(data: Record<string, unknown>): ParsedConfig {
  return { raw: JSON.stringify(data), format: 'json', filePath: '/tmp/cfg.json', data };
}

describe('NET-005: Active Connection Monitoring', () => {
  it('returns a valid CheckResult', async () => {
    const result = await net005.run(makeContext());
    expect(result.id).toBe('NET-005');
    expect(result.category).toBe('network');
    expect(result.severity).toBe('critical');
    expect(typeof result.passed).toBe('boolean');
    expect(typeof result.message).toBe('string');
  });

  it('is limited to darwin and linux platforms', () => {
    expect(net005.supportedPlatforms).toEqual(['darwin', 'linux']);
  });
});

describe('NET-001: Gateway Internet Exposure', () => {
  it('fails when gateway is bound to 0.0.0.0', async () => {
    const result = await net001.run(makeContext({ host: '0.0.0.0', port: 18789 }));
    expect(result.passed).toBe(false);
    expect(result.severity).toBe('critical');
  });

  it('fails when gateway is bound to [::]', async () => {
    const result = await net001.run(makeContext({ host: '::', port: 18789 }));
    expect(result.passed).toBe(false);
  });

  it('passes when gateway is bound to localhost', async () => {
    const result = await net001.run(makeContext({ host: '127.0.0.1', port: 18789 }));
    expect(result.passed).toBe(true);
  });

  it('passes when no gateway is configured', async () => {
    const result = await net001.run(makeContext(undefined));
    expect(result.passed).toBe(true);
  });
});

describe('NET-002: WebSocket Origin Validation', () => {
  it('fails when websocket.validateOrigin is explicitly false', async () => {
    const config = makeConfig({ websocket: { validateOrigin: false } });
    const result = await net002.run(makeContext(undefined, [config]));
    expect(result.passed).toBe(false);
    expect(result.severity).toBe('critical');
  });

  it('passes when validateOrigin is true', async () => {
    const config = makeConfig({ websocket: { validateOrigin: true } });
    const result = await net002.run(makeContext(undefined, [config]));
    expect(result.passed).toBe(true);
  });
});

describe('NET-003: Reverse Proxy Bypass', () => {
  it('fails when trustProxy=true (unrestricted)', async () => {
    const config = makeConfig({ trustProxy: true });
    const result = await net003.run(makeContext(undefined, [config]));
    expect(result.passed).toBe(false);
    expect(result.severity).toBe('warning');
  });

  it('passes when trustProxy is a specific IP allowlist', async () => {
    const config = makeConfig({ trustProxy: ['10.0.0.1'] });
    const result = await net003.run(makeContext(undefined, [config]));
    expect(result.passed).toBe(true);
  });
});

describe('NET-004: Agent Service Port Scan', () => {
  it('returns an info-level CheckResult and never fails the scan', async () => {
    const result = await net004.run(makeContext());
    expect(result.id).toBe('NET-004');
    expect(result.category).toBe('network');
    expect(result.severity).toBe('info');
    expect(result.passed).toBe(true); // info-only: always passes
  });
});
