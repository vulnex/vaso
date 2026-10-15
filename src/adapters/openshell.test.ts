import { describe, it, expect } from 'vitest';
import type { FSProvider } from '../core/fs-provider.js';
import type { ParsedConfig } from '../core/types.js';
import { openshellAdapter, resolveGateway } from './openshell.js';

const HOME = '/home/tester';

/** Files map to contents; a key ending in '/' declares an (empty) directory. */
function makeFs(files: Record<string, string>, opts: { platform?: NodeJS.Platform; env?: Record<string, string> } = {}): FSProvider {
  const paths = new Set<string>();
  for (const key of Object.keys(files)) {
    let p = key.endsWith('/') ? key.slice(0, -1) : key;
    paths.add(p);
    while ((p = p.slice(0, p.lastIndexOf('/'))) && p.length > 0) paths.add(p);
  }
  return {
    platform: opts.platform ?? 'linux',
    homedir: () => HOME,
    getEnv: (k: string) => opts.env?.[k],
    access: async (p: string) => paths.has(p),
    readFile: async (p: string) => {
      if (!(p in files)) throw new Error(`ENOENT ${p}`);
      return files[p];
    },
    readdirEntries: async () => [],
    execSync: () => { throw new Error('not found'); },
    exec: async () => ({ exitCode: 1, stdout: '', stderr: '' }),
  } as unknown as FSProvider;
}

const toml = (data: Record<string, unknown>): ParsedConfig => ({ raw: '', format: 'toml', filePath: '/g.toml', data });
const env = (data: Record<string, unknown>): ParsedConfig => ({ raw: '', format: 'env', filePath: '/g.env', data });

describe('OpenShell adapter', () => {
  it('detects a user gateway from ~/.config/openshell and loads gateway.toml', async () => {
    const fs = makeFs({
      [`${HOME}/.config/openshell/active_gateway`]: 'openshell',
      [`${HOME}/.config/openshell/gateway.toml`]: '[openshell]\nversion = 2\n\n[openshell.gateway]\nbind_address = "0.0.0.0:9000"\n',
      [`${HOME}/.local/state/openshell/gateway/openshell.db`]: '',
    });
    const [inst] = await openshellAdapter.detect({ fs });
    expect(inst.agent).toBe('openshell');
    expect(inst.installDir).toBe(`${HOME}/.config/openshell`);
    expect(inst.configFiles.map(c => c.filePath)).toEqual([`${HOME}/.config/openshell/gateway.toml`]);
    expect(inst.gateway).toMatchObject({ host: '0.0.0.0', port: 9000, tls: true, authMode: 'mtls' });
  });

  it('follows gateway.env to a redirected TOML (NemoClaw-managed gateway)', async () => {
    const nc = `${HOME}/.local/state/nemoclaw/openshell-docker-gateway`;
    const fs = makeFs({
      [`${HOME}/.config/openshell/gateway.env`]: `OPENSHELL_BIND_ADDRESS=127.0.0.1\nOPENSHELL_SERVER_PORT=8080\nOPENSHELL_GATEWAY_CONFIG=${nc}/openshell-gateway.toml\n`,
      [`${nc}/openshell-gateway.toml`]: '[openshell]\nversion = 1\n\n[openshell.gateway]\ncompute_drivers = ["docker"]\n',
    });
    const [inst] = await openshellAdapter.detect({ fs });
    expect(inst.configFiles.map(c => c.filePath)).toEqual([`${HOME}/.config/openshell/gateway.env`, `${nc}/openshell-gateway.toml`]);
    expect(inst.gateway).toMatchObject({ host: '127.0.0.1', port: 8080 });
  });

  it('uses the Homebrew prefix config on macOS when there is no user TOML', async () => {
    const fs = makeFs({
      [`${HOME}/.config/openshell/active_gateway`]: 'openshell',
      '/opt/homebrew/var/openshell/gateway.toml': '[openshell]\nversion = 2\n\n[openshell.gateway]\n',
    }, { platform: 'darwin' });
    const [inst] = await openshellAdapter.detect({ fs });
    expect(inst.configFiles.map(c => c.filePath)).toEqual(['/opt/homebrew/var/openshell/gateway.toml']);
    expect(inst.gateway).toMatchObject({ host: '127.0.0.1', port: 17670 });
  });

  it('honours $XDG_CONFIG_HOME for the scanning user', async () => {
    const fs = makeFs({ '/xdg/openshell/gateway.toml': '[openshell]\nversion = 2\n\n[openshell.gateway]\n' }, { env: { XDG_CONFIG_HOME: '/xdg' } });
    const [inst] = await openshellAdapter.detect({ fs });
    expect(inst.installDir).toBe('/xdg/openshell');
  });

  it('loads the snap gateway TOML from ~/snap/openshell/common, ahead of $SNAP_COMMON', async () => {
    const snap = `${HOME}/snap/openshell/common/.config/openshell/gateway.toml`;
    const fs = makeFs({
      [snap]: '[openshell]\nversion = 2\n\n[openshell.gateway]\nbind_address = "0.0.0.0:17670"\n',
      '/var/snap/openshell/common/gateway.toml': '[openshell]\nversion = 2\n\n[openshell.gateway]\n',
    });
    const [inst] = await openshellAdapter.detect({ fs });
    expect(inst.configFiles.map(c => c.filePath)).toEqual([snap]);
    expect(inst.gateway).toMatchObject({ host: '0.0.0.0' });
    // the older $SNAP_COMMON location is still the fallback
    const fallback = await openshellAdapter.detect({ fs: makeFs({ '/var/snap/openshell/common/gateway.toml': '[openshell]\nversion = 2\n\n[openshell.gateway]\n' }) });
    expect(fallback[0].configFiles.map(c => c.filePath)).toEqual(['/var/snap/openshell/common/gateway.toml']);
  });

  it('gives the probe a default workspace for sandboxes listed without one', () => {
    const cmd = openshellAdapter.getProbeManifest!().commands!.find(c => c.id === 'openshell-sandbox-policy');
    expect(cmd?.forEach).toMatchObject({ fields: ['name', 'workspace'], defaults: { workspace: 'default' } });
  });

  it('reports nothing without OpenShell state or CLI', async () => {
    expect(await openshellAdapter.detect({ fs: makeFs({ [`${HOME}/.bashrc`]: '' }) })).toEqual([]);
  });
});

describe('resolveGateway', () => {
  it('defaults to the loopback listener with TLS and mTLS auth', () => {
    expect(resolveGateway([])).toEqual({ host: '127.0.0.1', port: 17670, tls: true, authMode: 'mtls' });
  });

  it('lets the env file override the TOML', () => {
    const g = resolveGateway([
      env({ OPENSHELL_BIND_ADDRESS: '0.0.0.0', OPENSHELL_DISABLE_TLS: 'true' }),
      toml({ openshell: { gateway: { bind_address: '127.0.0.1:9000', disable_tls: false } } }),
    ]);
    expect(g).toMatchObject({ host: '0.0.0.0', port: 9000, tls: false });
  });

  it('reports unauthenticated and OIDC auth modes', () => {
    expect(resolveGateway([toml({ openshell: { gateway: { auth: { allow_unauthenticated_users: true } } } })]).authMode).toBe('none');
    expect(resolveGateway([toml({ openshell: { gateway: { oidc: { issuer: 'https://idp' } } } })]).authMode).toBe('oidc');
  });

  it('parses bracketed IPv6 bind addresses', () => {
    expect(resolveGateway([toml({ openshell: { gateway: { bind_address: '[::]:17670' } } })])).toMatchObject({ host: '::', port: 17670 });
  });
});
