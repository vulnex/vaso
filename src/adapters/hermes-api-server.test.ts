import { describe, it, expect } from 'vitest';
import type { ParsedConfig } from '../core/types.js';
import { hermesApiServer, hermesApiServerState } from './hermes-api-server.js';
import { hermesChecks } from '../checks/hermes/index.js';
import { cfg001 } from '../checks/config/cfg-001-gateway-binding.js';

const KEY = 'a3f9c27e5b1d4086f2e7';
const yaml = (data: Record<string, unknown>, managed = false): ParsedConfig =>
  ({ raw: '', format: 'yaml', filePath: managed ? '/etc/hermes/config.yaml' : '/h/.hermes/config.yaml', data, ...(managed ? { managed } : {}) });
const env = (data: Record<string, string>): ParsedConfig =>
  ({ raw: '', format: 'env', filePath: '/h/.hermes/.env', data });
const active = (configs: ParsedConfig[], version?: string) => hermesApiServer(configs, version).active;

describe('Hermes API server: enabled the way each release decides it', () => {
  it('a host, key or CORS list alone starts nothing', () => {
    for (const v of ['0.8.0', '0.20.0', '0.21.6', undefined]) {
      expect(active([env({ API_SERVER_HOST: '0.0.0.0' })], v), v).toBe(false);
      expect(active([yaml({ gateway: { api_server: { host: '0.0.0.0', key: KEY, cors_origins: '*' } } })], v), v).toBe(false);
    }
    expect(active([yaml({ gateway: { api_server: { enabled: true, host: '0.0.0.0' } } })], '0.8.0')).toBe(true);
  });

  it('config enabled: false keeps it off', () => {
    const off = yaml({ gateway: { api_server: { enabled: false, host: '0.0.0.0', key: KEY, cors_origins: '*' } } });
    for (const v of ['0.8.0', '0.20.0', '0.21.6', undefined]) {
      expect(hermesApiServerState(hermesApiServer([off], v), v), v).toBe('disabled');
    }
  });

  it('before 0.19.1 the env enables it over a config enabled: false; from 0.19.1 the explicit disable wins', () => {
    const off = yaml({ platforms: { api_server: { enabled: false } } });
    expect(active([off, env({ API_SERVER_KEY: 'k' })], '0.8.0')).toBe(true);
    expect(active([off, env({ API_SERVER_ENABLED: 'true' })], '0.18.0')).toBe(true);
    expect(active([off, env({ API_SERVER_KEY: KEY })], '0.19.0')).toBe(true);
    expect(active([off, env({ API_SERVER_KEY: KEY })], '0.19.1')).toBe(false);
    // `enabled: null` is still an explicit key (`_enabled_explicit`)
    expect(active([yaml({ gateway: { api_server: { enabled: null } } }), env({ API_SERVER_KEY: KEY })], '0.21.6')).toBe(false);
    // Without any config `enabled`, a usable env key enables it
    expect(active([env({ API_SERVER_KEY: KEY })], '0.21.6')).toBe(true);
  });

  it('reads API_SERVER_ENABLED with each release\'s truthiness, and not at all from 0.19.1', () => {
    expect(active([env({ API_SERVER_ENABLED: 'yes' })], '0.8.0')).toBe(true);
    expect(active([env({ API_SERVER_ENABLED: 'on' })], '0.18.0')).toBe(false);
    expect(active([env({ API_SERVER_ENABLED: ' true' })], '0.18.0')).toBe(false);
    expect(active([env({ API_SERVER_ENABLED: 'on' })], '0.19.0')).toBe(true);
    expect(active([env({ API_SERVER_ENABLED: 'true' })], '0.21.6')).toBe(false);
    // …while any key enabled it before 0.19.1, API_SERVER_ENABLED=false included
    expect(active([env({ API_SERVER_ENABLED: 'false', API_SERVER_KEY: 'k' })], '0.18.0')).toBe(true);
    expect(active([env({ API_SERVER_ENABLED: 'false', API_SERVER_KEY: KEY })], '0.21.6')).toBe(true);
  });

  it('coerces a config enabled from 0.12.0; earlier releases took Python truthiness', () => {
    const quoted = yaml({ gateway: { api_server: { enabled: 'false' } } });
    expect(active([quoted], '0.11.0')).toBe(true);
    expect(active([quoted], '0.12.0')).toBe(false);
    // PyYAML loads an unquoted off/yes as a boolean
    expect(active([yaml({ platforms: { api_server: { enabled: 'off' } } })], '0.8.0')).toBe(false);
    expect(active([yaml({ platforms: { api_server: { enabled: 'yes' } } })], '0.8.0')).toBe(true);
    expect(active([yaml({ platforms: { api_server: { enabled: 'maybe' } } })], '0.21.6')).toBe(false);
    expect(active([yaml({ platforms: { api_server: { enabled: 1 } } })], '0.21.6')).toBe(true);
  });

  it('the later platform block and the managed layer win', () => {
    const both = yaml({ gateway: { api_server: { enabled: true } }, platforms: { api_server: { enabled: false } } });
    expect(active([both], '0.21.6')).toBe(true);
    const user = yaml({ gateway: { api_server: { enabled: true, host: '0.0.0.0' } } });
    expect(active([user, yaml({ gateway: { api_server: { enabled: false } } }, true)], '0.21.6')).toBe(false);
  });
});

describe('Hermes API server checks skip a server that is not enabled', () => {
  const hm004 = hermesChecks.find(c => c.id === 'HM-004')!;
  const hm005 = hermesChecks.find(c => c.id === 'HM-005')!;
  const ctx = (configs: ParsedConfig[], version?: string) => ({
    installation: { agent: 'hermes' as const, installDir: '/h/.hermes', configFiles: configs, version },
    configs,
    platform: 'linux' as const,
    fs: {} as never,
  });

  it('HM-004 / CFG-001: host-only and enabled: false on a release without the key guard', async () => {
    for (const configs of [
      [env({ API_SERVER_HOST: '0.0.0.0' })],
      [yaml({ gateway: { api_server: { enabled: false, host: '0.0.0.0' } } })],
    ]) {
      expect((await hm004.run(ctx(configs, '0.8.0'))).passed).toBe(true);
      expect((await cfg001.run(ctx(configs, '0.8.0'))).passed).toBe(true);
    }
    // Enabled, it is still reported
    const on = [yaml({ gateway: { api_server: { enabled: true, host: '0.0.0.0' } } })];
    expect((await hm004.run(ctx(on, '0.8.0'))).severity).toBe('critical');
    expect((await hm004.run(ctx(on, '0.8.0'))).passed).toBe(false);
    expect((await cfg001.run(ctx(on, '0.8.0'))).passed).toBe(false);
  });

  it('HM-005: wildcard CORS on a disabled server, and on an enabled one', async () => {
    const block = { host: '0.0.0.0', key: KEY, cors_origins: '*' };
    expect((await hm005.run(ctx([yaml({ gateway: { api_server: { enabled: false, ...block } } })], '0.20.0'))).passed).toBe(true);
    expect((await hm005.run(ctx([yaml({ gateway: { api_server: block } })]))).passed).toBe(true);
    expect((await hm005.run(ctx([yaml({ gateway: { api_server: { enabled: true, ...block } } })], '0.20.0'))).passed).toBe(false);
    expect((await hm005.run(ctx([yaml({ gateway: { api_server: block } }), env({ API_SERVER_KEY: KEY })]))).passed).toBe(false);
  });
});
